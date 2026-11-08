#!/bin/bash
set -euo pipefail

relay=no
vrfy=no
catchall=no
case "${SMTP_PROFILE:?}" in
  vrfy) vrfy=yes ;;
  rcpt) ;;
  catchall) catchall=yes ;;
  open_relay) vrfy=yes; relay=yes ;;
  *) echo 'Unknown SMTP_PROFILE' >&2; exit 2 ;;
esac
sed -e "s/RELAY_VALUE/$relay/" -e "s/VRFY_VALUE/$vrfy/" -e "s/CATCHALL_VALUE/$catchall/" \
  /etc/exim4/module-target.conf > /etc/exim4/exim4.conf
exec exim4 -bdf -q10s
