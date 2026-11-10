#!/bin/sh
set -eu
sed -i "s/ALWAYS_AUTH_REJECT/${ALWAYS_AUTH_REJECT:-no}/" /etc/asterisk/sip.conf
sed -i "s/AUTH_OPTIONS_REQUESTS/${AUTH_OPTIONS_REQUESTS:-no}/" /etc/asterisk/sip.conf
# Keep the ordinary profiles unchanged; this opt-in permits legacy untagged requests.
if [ "${SIP_PEDANTIC:-}" = no ]; then
  printf '\n[general](+)\npedantic=no\n' >> /etc/asterisk/sip.conf
fi
chown -R asterisk:asterisk /run/asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk
exec "$@"
