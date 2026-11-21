#!/bin/sh
set -eu
printf '%s' 'preserve-redis-foreign' > /tmp/module-target-redis-foreign
exec redis-server --bind 0.0.0.0 --protected-mode no --dir /tmp --save '' \
  --appendonly no --requirepass "${REDIS_LAB_PASSWORD:-}"
