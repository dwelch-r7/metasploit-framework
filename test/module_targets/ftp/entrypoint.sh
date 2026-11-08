#!/bin/bash
set -euo pipefail

case "${ANONYMOUS_MODE:?}" in
  read_write) login=AllowAll; write=AllowAll ;;
  read_only) login=AllowAll; write=DenyAll ;;
  denied) login=DenyAll; write=DenyAll ;;
  *) echo 'Unknown ANONYMOUS_MODE' >&2; exit 2 ;;
esac
sed -e "s/ANONYMOUS_LOGIN/$login/" -e "s/ANONYMOUS_WRITE/$write/" \
  /etc/proftpd/module-target.conf > /etc/proftpd/target.conf
exec proftpd --nodaemon --debug 2 --config /etc/proftpd/target.conf
