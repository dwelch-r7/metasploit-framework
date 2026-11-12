#!/bin/sh
set -eu
mkdir -p /unifi/data /unifi/log /unifi/proofs
# The image supports these database settings. Disable preallocated journals in
# this disposable lab; do not change Log4j, JNDI or authentication behavior.
if ! test -f /unifi/data/system.properties; then
  printf '%s\n' 'unifi.db.nojournal=true' 'unifi.db.extraargs=--quiet' > /unifi/data/system.properties
fi
chown -R unifi:unifi /unifi
