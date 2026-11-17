#!/bin/sh
set -eu
# Fresh anonymous web volume only; never replace an existing installation.
test ! -e wp-includes/version.php
php /opt/module-target/verify-archive.php
tar -xzf /opt/module-target/core.tar.gz --strip-components=1
chown -R www-data:www-data .
exec /usr/local/bin/docker-entrypoint.sh "$@"
