#!/bin/sh
set -eu
python3 /opt/credential-fixture/seed.py
ssh-keygen -A
/usr/sbin/sshd -e
cd /opt/gemstash
bundle exec gemstash start --config-file /opt/credential-fixture/gemstash.yml > /opt/credential-state/gemstash-console.log 2>&1 &
exec python3 -m http.server 8080 --bind 0.0.0.0 --directory /opt/health
