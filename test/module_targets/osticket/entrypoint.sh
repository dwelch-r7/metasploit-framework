#!/bin/sh
set -eu
OSTICKET_ROOT="/var/www/html${LAB_PREFIX:-}"
export OSTICKET_ROOT
mkdir -p "$OSTICKET_ROOT"
if [ ! -f "$OSTICKET_ROOT/bootstrap.php" ]; then
  cp -a /opt/osticket/source/upload/. "$OSTICKET_ROOT/"
fi
if [ ! -f "$OSTICKET_ROOT/include/ost-config.php" ]; then
  cp "$OSTICKET_ROOT/include/ost-sampleconfig.php" "$OSTICKET_ROOT/include/ost-config.php"
fi
chown -R www-data:www-data "$OSTICKET_ROOT"
exec docker-php-entrypoint "$@"
