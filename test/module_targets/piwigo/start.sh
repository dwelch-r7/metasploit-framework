#!/bin/sh
set -eu
piwigo_root="/var/www/html${LAB_PREFIX:-}"
mkdir -p "$piwigo_root"
cp -a /opt/module-target/source/. "$piwigo_root/"
chown -R www-data:www-data "$piwigo_root"
touch /tmp/module-target-piwigo-copied
exec docker-php-entrypoint "$@"
