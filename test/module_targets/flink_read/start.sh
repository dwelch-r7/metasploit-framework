#!/bin/sh
set -eu
mkdir -p /opt/flink/fixtures/nested /opt/flink/uploads
printf 'module-target-flink-file\nSecond line: spaces / %% + & =\n' > /opt/flink/fixtures/public.txt
printf 'module-target-flink-nested\n' > '/opt/flink/fixtures/nested/space name.txt'
: > /opt/flink/fixtures/empty.txt
printf 'module-target-flink-protected\n' > /root/module-target-protected
chmod 600 /root/module-target-protected
: > /opt/flink/log/module-target-jobmanager.log
chown -R flink:flink /opt/flink/fixtures /opt/flink/uploads /opt/flink/log
exec /docker-entrypoint.sh "$@"
