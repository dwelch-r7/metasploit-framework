#!/bin/bash
set -euo pipefail

# This historical image predates docker-entrypoint-initdb.d. Provision through
# its real local daemon, stop it cleanly, then start the final auth policy.
mongod --fork --bind_ip 127.0.0.1 --smallfiles --noprealloc --nojournal --logpath /tmp/mongodb-init.log
mongo --quiet admin /opt/seed.js
mongod --shutdown --dbpath /data/db
arguments=(mongod --bind_ip 0.0.0.0 --smallfiles --noprealloc --nojournal)
if [[ "${AUTH_ENABLED:?}" == true ]]; then
  arguments+=(--auth)
fi
exec /entrypoint.sh "${arguments[@]}"
