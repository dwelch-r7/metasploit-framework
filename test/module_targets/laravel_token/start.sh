#!/bin/sh
set -eu
cd /var/www
php /opt/module-target-setup.php
php artisan package:discover --no-ansi
chown -R www-data:www-data storage bootstrap/cache
exec apache2-foreground
