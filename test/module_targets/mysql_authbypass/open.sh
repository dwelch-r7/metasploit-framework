#!/bin/bash
set -eu
mysqld_safe > /tmp/module-target-seed-server.log 2>&1 &
seed_server=$!
for ((attempt=1; attempt<=100; attempt++)); do
 if mysql --protocol=TCP --host=127.0.0.1 --user=root --password=123456 --execute='SELECT 1' >/dev/null 2>&1; then break; fi
 sleep 0.2
done
mysql --protocol=TCP --host=127.0.0.1 --user=root --password=123456 < /opt/module-target/seed.sql
mysqladmin --protocol=TCP --host=127.0.0.1 --user=root --password=123456 shutdown
wait "$seed_server"
touch /tmp/module-target-open-ready
exec mysqld_safe --skip-grant-tables
