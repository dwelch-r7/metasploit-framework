#!/bin/sh
set -eu
if ! id labuser >/dev/null 2>&1; then
  useradd --uid 1001 --create-home --shell /bin/bash labuser
fi
mkdir -p /opt/module-target-artifacts
test ! -e /root/.netrc
test ! -e /home/labuser/.netrc
exec python3 -m http.server 8080 --bind 0.0.0.0 --directory /opt/health
