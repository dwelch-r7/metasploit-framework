#!/bin/sh
set -eu
session_directory='/tmp/module-target-session-storage with spaces'
if [ -e "$session_directory" ]; then
  echo 'Native session directory unexpectedly exists' >&2
  exit 1
fi
mkdir -m 700 "$session_directory"
exec /bin/sh /opt/module-target/start.sh
