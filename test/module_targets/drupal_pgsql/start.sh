#!/bin/sh
set -eu
php -r '$catalog=json_decode(file_get_contents("/opt/module-target/releases.json"),true);$release=$catalog[getenv("DRUPAL_RELEASE")];if(!hash_equals($release["sha256"],hash_file("sha256","/opt/module-target/drupal.tar.gz"))){fwrite(STDERR,"Drupal archive checksum differs\n");exit(1);}'
mkdir -p /var/www/module-target-drupal
tar -xzf /opt/module-target/drupal.tar.gz --strip-components=1 -C /var/www/module-target-drupal
cp /opt/module-target/drupal.conf /etc/apache2/conf-available/module-target-drupal.conf
sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/module-target-drupal|' /etc/apache2/sites-available/000-default.conf
if [ -n "${LAB_PREFIX:-}" ]; then
  test "$LAB_PREFIX" = /lab
  mkdir -p /var/www/module-target-public
  sed -i 's|DocumentRoot /var/www/module-target-drupal|DocumentRoot /var/www/module-target-public|' /etc/apache2/sites-available/000-default.conf
  printf 'Alias "%s/" "/var/www/module-target-drupal/"\n<Directory /var/www/module-target-drupal>\n  RewriteBase %s/\n</Directory>\n' "$LAB_PREFIX" "$LAB_PREFIX" >> /etc/apache2/conf-available/module-target-drupal.conf
fi
a2enmod rewrite
a2enconf module-target-drupal
php -d memory_limit=512M /opt/module-target/install.php
php -d memory_limit=512M /opt/module-target/configure.php
chown -R www-data:www-data /var/www/module-target-drupal/sites
printf 'ready\n' > /tmp/module-target-drupal-pgsql-ready
exec apache2-foreground
