#!/bin/sh
set -eu
python /opt/module-target-netalertx/bootstrap.py
python /opt/module-target-execution/configure.py
# The shipped s6-overlay must own PID 1. It starts real PHP, backend and cron.
exec /init
