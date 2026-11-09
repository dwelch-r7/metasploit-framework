#!/bin/sh
set -eu

app="/var/www/html${LAB_PREFIX}"
php /opt/module-target/seed.php "$app"
rm -rf "$app/installation"
chown -R www-data:www-data /var/www/html
if [ "${LAB_HIDE_VERSION:-0}" = 1 ]; then
  cp /opt/module-target/hidden.conf /etc/apache2/conf-enabled/module-target-hidden.conf
fi
touch /tmp/module-target-ready
exec apache2-foreground
