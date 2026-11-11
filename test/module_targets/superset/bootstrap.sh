#!/bin/sh
# Use supported initialization commands, then the unchanged vendor launcher.
# apache/superset 067495d954ee0015d35c1437245feb66984e4c49 Dockerfile
# copies docker/run-server.sh to /usr/bin and runs it as user superset.
set -eu
superset db upgrade
superset fab create-admin --username lab-admin --firstname Module --lastname Admin --email admin@module-target.test --password module-target-superset-admin-password
superset init
exec /usr/bin/run-server.sh
