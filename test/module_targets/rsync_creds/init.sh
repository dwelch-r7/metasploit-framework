#!/bin/sh
set -eu
if ! id labuser >/dev/null 2>&1; then
  useradd --uid 1001 --create-home --shell /bin/bash labuser
fi
mkdir -p /opt/module-target-artifacts
exec rsync --daemon --no-detach --config /etc/rsyncd.conf
