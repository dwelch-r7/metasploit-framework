#!/bin/sh
set -eu
cd /var/www
install -o www-data -g www-data -m 0600 /dev/null storage/logs/laravel.log
exec apache2-foreground
