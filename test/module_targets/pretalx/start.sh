#!/bin/bash
set -euo pipefail
mkdir -p /data/logs /data/media
python -m pretalx migrate --noinput
python /lab/bootstrap.py
if [ "${PRETALX_DEBUG:-False}" = "True" ]; then
  # Debug renders unhashed static URLs; exports still require an offline
  # compression manifest generated for those genuine template inputs.
  PRETALX_REDIS=False python /lab/assets.py
fi
celery -A pretalx.celery_app worker --concurrency=1 --pool=solo --loglevel=info --without-gossip --without-mingle --without-heartbeat &
worker=$!
trap 'kill "$worker" 2>/dev/null || true' EXIT
gunicorn pretalx.wsgi --workers 1 --threads 1 --bind 0.0.0.0:8000 --access-logfile - --error-logfile - &
web=$!
trap 'kill "$web" "$worker" 2>/dev/null || true; wait || true' EXIT TERM INT
wait -n "$web" "$worker"
