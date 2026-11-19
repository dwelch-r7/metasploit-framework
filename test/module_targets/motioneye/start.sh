#!/bin/sh
set -eu
python3 /opt/module-target/camera.py > /tmp/module-target-motioneye-camera.log 2>&1 &
printf '%s\n' "$!" > /tmp/module-target-motioneye-camera.pid
exec /entrypoint.sh
