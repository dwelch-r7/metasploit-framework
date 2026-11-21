#!/bin/sh
set -eu
mkdir -p /home/app/library
calibredb list --with-library /home/app/library --for-machine
if [ "${SEED_BOOK:-true}" = true ]; then
  calibredb add --empty --title 'Module target calibration' --authors 'Module Target' --with-library /home/app/library
fi
exec calibre-server --listen-on 0.0.0.0 --port 8080 --log /home/app/calibre.log --access-log /home/app/access.log /home/app/library
