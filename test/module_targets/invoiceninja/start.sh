#!/bin/sh
set -eu
cd /var/www/app
cp .env.example .env
mkdir -p storage/framework/cache/data storage/framework/sessions storage/framework/views storage/logs
php artisan migrate --seed --force --no-interaction
# Migrations alone leave /login failing before the first account is installed.
php artisan ninja:create-account --email=module-target@example.test --password=ModuleTarget-Ninja-2026 --no-interaction
cd public
exec php -S 0.0.0.0:8080 ../vendor/laravel/framework/src/Illuminate/Foundation/resources/server.php
