#!/bin/sh
set -eu
mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs
touch storage/module-target.sqlite
php artisan migrate --seed --force --no-interaction
php /opt/module-target-setup.php
cd public
exec php -S 0.0.0.0:8080 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php
