#!/bin/sh
set -eu
install_root="/var/www/html${LAB_PREFIX:-}"
mkdir -p "$install_root"
cp -a /opt/drupal/. "$install_root/"
cp "$install_root/sites/default/default.settings.php" "$install_root/sites/default/settings.php"
chown -R www-data:www-data "$install_root"
if [ "${LAB_ASSERT_OFF:-0}" = 1 ]; then
  printf 'assert.active = 0\n' > /usr/local/etc/php/conf.d/zz-module-target-assert-off.ini
fi
cd "$install_root"
su -s /bin/sh -c 'php /opt/module-target/seed.php' www-data
if [ "${LAB_NO_CHANGELOG:-0}" = 1 ]; then
  mv CHANGELOG.txt /opt/module-target/drupal-CHANGELOG.txt
fi
exec apache2-foreground
