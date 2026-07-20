#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r'''
Created by Marcin Ulikowski <marcin@ulikowski.pl>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import os
import collections
import logging
from queue import Queue
from uuid import uuid4
import time
import threading
from flask import Flask, request, jsonify, send_from_directory
import dnstwist

LOG = logging.getLogger('webapp')


PORT = int(os.environ.get('PORT', 8000))
HOST = os.environ.get('HOST', '127.0.0.1')


def bind_address(host=None, port=None):
	'''Format host:port for servers like gunicorn (IPv6 addresses need brackets).'''
	host = host if host is not None else HOST
	port = port if port is not None else PORT
	if ':' in host:
		return '[{}]:{}'.format(host, port)
	return '{}:{}'.format(host, port)
THREADS = int(os.environ.get('THREADS', dnstwist.THREAD_COUNT_DEFAULT))
NAMESERVERS = os.environ.get('NAMESERVERS') or os.environ.get('NAMESERVER')
SESSION_TTL = int(os.environ.get('SESSION_TTL', 3600))
MAX_CONCURRENT = int(os.environ.get('SESSION_MAX', 10)) # max concurrently running scans
MAX_QUEUE = int(os.environ.get('MAX_QUEUE', 500)) # max queued scans before backpressure
DOMAIN_MAXLEN = int(os.environ.get('DOMAIN_MAXLEN', 15))
WEBAPP_HTML = os.environ.get('WEBAPP_HTML', 'webapp.html')
WEBAPP_DIR = os.environ.get('WEBAPP_DIR', os.path.dirname(os.path.abspath(__file__)))
BATCHING_INTERVAL = float(os.environ.get('BATCHING_INTERVAL', 0.2))

DOMAIN_BLOCKLIST = []

DICTIONARY = ('auth', 'account', 'confirm', 'connect', 'enroll', 'http', 'https', 'info', 'login', 'mail', 'my',
	'online', 'payment', 'portal', 'recovery', 'register', 'ssl', 'safe', 'secure', 'signin', 'signup', 'support',
	'update', 'user', 'verify', 'verification', 'web', 'www', 'airdrop', 'bounty', 'ico', 'token', 'air', 'drop', 
	'alert', 'bridge', 'card', 'chrome', 'contact', 'crypto', 'crypto', 'dao', 'defi', 'extension', 'guard', 'key',
	'help', 'helpdesk', 'homepage', 'hub', 'import', 'inbox', 'ipo', 'kyc', 'launch', 'launchpad', 'portfolio',
	'private', 'receive', 'rewards', 'recover', 'redeem', 'return', 'seed', 'sign', 'signature', 'swap', 'stake',
	'staking', 'wallet', 'whitelist', 'eligible', 'eligibility', 'web3')
TLD_DICTIONARY = ('com', 'net', 'org', 'info', 'cn', 'co', 'eu', 'de', 'uk', 'pw', 'ga', 'gq', 'tk', 'ml', 'cf',
	'app', 'biz', 'top', 'xyz', 'online', 'site', 'live')


sessions = []
pending = collections.deque() # FIFO of queued sessions awaiting a free slot
lock = threading.Lock() # guards mutations of sessions/pending
dispatcher_thread = None
janitor_thread = None
app = Flask(__name__)

def janitor(sessions):
	'''Reap finished scans and expire stale ones, once per second, forever.

	Snapshots the session list under the lock (never iterates live shared state),
	stops scans whose work is done, and drops sessions older than SESSION_TTL.
	Queued sessions are TTL-exempt so a backlog can't evict a scan before it runs
	(pending is bounded by MAX_QUEUE instead). A still-running session past TTL is
	stopped with reason='expired' so its workers are joined rather than orphaned.
	Each pass is guarded so one bad session can't kill the reaper.
	'''
	while True:
		time.sleep(1)
		try:
			with lock:
				snapshot = sorted(sessions, key=lambda x: x.timestamp)
		except Exception:
			LOG.exception('janitor snapshot failed')
			continue
		for s in snapshot:
			try:
				if s.jobs.empty() and s.threads:
					s.stop()
					continue
				if s.state != 'queued' and (s.timestamp + SESSION_TTL) < time.time():
					s.stop(reason='expired')
					with lock:
						if s in sessions:
							sessions.remove(s)
						if s in pending:
							pending.remove(s)
			except Exception:
				LOG.exception('janitor failed while processing session %s', getattr(s, 'id', '?'))

def dispatch_once():
	'''Promote queued sessions to running while under the MAX_CONCURRENT cap.

	Pops the FIFO pending queue and starts each scan. Each session is claimed under
	its own lock so a concurrent stop() can't slip between the state check and
	scan(). A scan that fails to launch is marked 'error' instead of killing the
	dispatcher, and draining continues.
	'''
	with lock:
		snapshot = list(sessions)
	running = sum(1 for s in snapshot if s.state == 'running' and s.threads)
	while running < MAX_CONCURRENT:
		with lock:
			if not pending:
				break
			s = pending.popleft()
		with s.lock:
			if s.state != 'queued':
				continue
			try:
				s.scan()
			except Exception:
				LOG.exception('scan() failed to start for session %s', s.id)
				s.stop(reason='error')
				continue
		running += 1

def dispatcher():
	'''Drive dispatch_once() every BATCHING_INTERVAL, surviving any iteration error.'''
	while True:
		time.sleep(BATCHING_INTERVAL)
		try:
			dispatch_once()
		except Exception:
			LOG.exception('dispatcher iteration failed')

class Session():
	'''A single scan job and its lifecycle.

	State machine: queued -> {cancelled, running -> {done, error, expired}}
	  queued    - accepted, waiting for a free dispatcher slot
	  running   - workers actively resolving permutations
	  done      - finished naturally, or stopped by the user
	  cancelled - stopped while still queued (never ran)
	  error     - scan() failed to launch (e.g. thread exhaustion); no results
	  expired   - truncated mid-run by the TTL janitor; partial results are real

	self.lock (reentrant) guards every state transition so status(), the
	dispatcher, and stop() never observe a half-applied change.
	'''
	def __init__(self, url, nameservers=None, thread_count=THREADS):
		self.id = str(uuid4())
		self.timestamp = int(time.time())
		self.url = dnstwist.UrlParser(url)
		self.nameservers = nameservers
		self.thread_count = thread_count
		self.jobs = Queue()
		self.threads = []
		self.state = 'queued'
		self._final_remaining = None # progress frozen at cutoff for 'expired' scans
		self.lock = threading.RLock()
		self.fuzzer = dnstwist.Fuzzer(self.url.domain, dictionary=DICTIONARY, tld_dictionary=TLD_DICTIONARY)
		self.fuzzer.generate()
		self.permutations = self.fuzzer.permutations

	def scan(self):
		self.state = 'running'
		for domain in self.fuzzer.domains:
			self.jobs.put(domain)
		for _ in range(self.thread_count):
			worker = dnstwist.Scanner(self.jobs)
			worker.option_extdns = dnstwist.MODULE_DNSPYTHON
			worker.option_geoip = dnstwist.MODULE_GEOIP
			if self.nameservers:
				worker.nameservers = self.nameservers.split(',')
			worker.start()
			self.threads.append(worker)

	def stop(self, reason='done'):
		'''Terminate the scan and record how it ended.

		reason is the terminal state for a session that had already started: 'done'
		(natural finish or user stop), 'error' (failed to launch), or 'expired'
		(truncated mid-run by the TTL janitor). A still-queued session becomes
		'cancelled' with nothing to tear down. Idempotent - a second call on an
		already-terminal session is a no-op. For 'expired', outstanding progress is
		frozen before the queue is cleared so status() can report a truthful
		partial. Worker stop()/join() runs outside the lock so status() only ever
		blocks on the brief state mutation, not the teardown.
		'''
		with self.lock:
			if self.state in ('done', 'cancelled', 'error', 'expired'):
				return
			if self.state == 'queued':
				self.state = 'cancelled'
				return
			if reason == 'expired':
				self._final_remaining = max(self.jobs.qsize(), len(self.threads))
			self.state = reason
			workers = list(self.threads)
			self.threads.clear()
			self.jobs.queue.clear()
		for worker in workers:
			worker.stop()
		for worker in workers:
			worker.join()

	def domains(self):
		return self.permutations(registered=True, unicode=True)

	def status(self):
		'''Return a JSON-able progress snapshot, read under the lock.

		Holding self.lock prevents a torn read against a concurrent stop(): without
		it, state could be seen as 'running' and then jobs/threads read as
		already-cleared, falsely reporting 100% completion. Non-progress terminal
		states (queued/cancelled/error) report complete=0; 'expired' reports the
		partial frozen at cutoff; running/done compute from live counts.
		'''
		with self.lock:
			total = len(self.permutations())
			if self.state in ('queued', 'cancelled', 'error'):
				remaining = total
				complete = 0
			elif self.state == 'expired':
				remaining = self._final_remaining if self._final_remaining is not None else 0
				complete = total - remaining
			else:
				remaining = max(self.jobs.qsize(), len(self.threads))
				complete = total - remaining
			registered = len(self.permutations(registered=True))
			return {
				'id': self.id,
				'timestamp': self.timestamp,
				'url': self.url.full_uri(),
				'domain': self.url.domain,
				'total': total,
				'complete': complete,
				'remaining': remaining,
				'registered': registered,
				'state': self.state
				}

	def csv(self):
		return dnstwist.Format(self.permutations(registered=True)).csv()

	def json(self):
		return dnstwist.Format(self.permutations(registered=True)).json()

	def list(self):
		return dnstwist.Format(self.permutations()).list()


@app.route('/')
def root():
	return send_from_directory(WEBAPP_DIR, WEBAPP_HTML)

@app.route('/_health')
def healthcheck():
	'''Liveness probe: 503 if the dispatcher or janitor thread has died.'''
	for name, thread in (('dispatcher', dispatcher_thread), ('janitor', janitor_thread)):
		if thread is not None and not thread.is_alive():
			return '{} not running'.format(name), 503
	return 'healthy'

@app.route('/api/scans', methods=['POST'])
def api_scan():
	'''Accept and enqueue a scan; the dispatcher starts it when a slot frees up.

	MAX_QUEUE backpressure is applied twice: an unlocked fast check up front to
	skip the expensive fuzzer.generate() for requests that would be rejected, and
	an authoritative re-check under the lock so concurrent bursts can't overshoot.
	'''
	if len(pending) >= MAX_QUEUE:
		return jsonify({'message': 'Too many scan sessions - please retry in a minute'}), 429, {'Retry-After': '60'}
	j = request.get_json(force=True)
	if 'url' not in j:
		return jsonify({'message': 'Bad request'}), 400
	try:
		_, domain, _ = dnstwist.domain_tld(j.get('url'))
	except Exception:
		return jsonify({'message': 'Bad request'}), 400
	if len(domain) > DOMAIN_MAXLEN:
		return jsonify({'message': 'Domain name is too long'}), 400
	for block in DOMAIN_BLOCKLIST:
		if str(block) in domain:
			return jsonify({'message': 'Not allowed'}), 400
	try:
		session = Session(j.get('url'), nameservers=NAMESERVERS)
	except Exception as err:
		return jsonify({'message': 'Invalid domain name'}), 400
	else:
		with lock:
			if len(pending) >= MAX_QUEUE:
				return jsonify({'message': 'Too many scan sessions - please retry in a minute'}), 429, {'Retry-After': '60'}
			sessions.append(session)
			pending.append(session)
	return jsonify(session.status()), 201


@app.route('/api/scans/<sid>')
def api_status(sid):
	for s in sessions:
		if s.id == sid:
			return jsonify(s.status())
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/domains')
def api_domains(sid):
	for s in sessions:
		if s.id == sid:
			return jsonify(s.domains())
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/csv')
def api_csv(sid):
	for s in sessions:
		if s.id == sid:
			return s.csv(), 200, {'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename=dnstwist.csv'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/json')
def api_json(sid):
	for s in sessions:
		if s.id == sid:
			return s.json(), 200, {'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename=dnstwist.json'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/list')
def api_list(sid):
	for s in sessions:
		if s.id == sid:
			return s.list(), 200, {'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename=dnstwist.txt'}
	return jsonify({'message': 'Scan session not found'}), 404


@app.route('/api/scans/<sid>/stop', methods=['POST'])
def api_stop(sid):
	'''Stop a scan and free its queue slot so it stops counting toward MAX_QUEUE.'''
	for s in sessions:
		if s.id == sid:
			s.stop()
			with lock:
				if s in pending:
					pending.remove(s)
			return jsonify({})
	return jsonify({'message': 'Scan session not found'}), 404


def start_background_threads():
	'''Launch the janitor and dispatcher daemon threads for this process.'''
	global janitor_thread, dispatcher_thread
	janitor_thread = threading.Thread(target=janitor, args=(sessions,))
	janitor_thread.daemon = True
	janitor_thread.start()

	dispatcher_thread = threading.Thread(target=dispatcher)
	dispatcher_thread.daemon = True
	dispatcher_thread.start()

# Start on import so each server process gets its own threads; tests opt out via
# WEBAPP_START_THREADS=0. State and limits are per-process, so keep WORKERS=1.
if os.environ.get('WEBAPP_START_THREADS', '1') != '0':
	start_background_threads()

if __name__ == '__main__':
	app.run(host=HOST, port=PORT)
