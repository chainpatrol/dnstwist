#!/bin/sh
set -e

HOST="${HOST:-::}"
PORT="${PORT:-8000}"

if echo "$HOST" | grep -q ':'; then
	BIND="[$HOST]:$PORT"
else
	BIND="$HOST:$PORT"
fi

exec gunicorn3 webapp:app \
	--bind "$BIND" \
	--workers "${WORKERS:-1}" \
	--threads "${GUNICORN_THREADS:-3}" \
	--log-level "${LOG_LEVEL:-debug}"
