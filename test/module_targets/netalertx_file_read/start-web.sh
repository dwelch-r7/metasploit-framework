#!/bin/sh
set -eu
python /opt/module-target-netalertx/bootstrap.py
chown -R nginx:www-data /app/config /app/db /app/front/log /app/front/api
mkdir -p /run/php /run/nginx /var/lib/php83/sessions
chown nginx:www-data /var/lib/php83/sessions
# Use the vendor's generated FPM configuration and unmodified NGINX template.
export INSTALL_DIR=/app
envsubst '$INSTALL_DIR $LISTEN_ADDR $PORT' < /app/install/netalertx.template.conf > /etc/nginx/http.d/netalertx.conf
# Keep worker counts proportionate to this single-request fixture.
sed -i 's/^worker_processes .*/worker_processes 1;/' /etc/nginx/nginx.conf
sed -i -e 's/^pm.max_children =.*/pm.max_children = 3/' -e 's/^pm.start_servers =.*/pm.start_servers = 1/' -e 's/^pm.min_spare_servers =.*/pm.min_spare_servers = 1/' -e 's/^pm.max_spare_servers =.*/pm.max_spare_servers = 2/' /etc/php83/php-fpm.d/www.conf
php-fpm83 -F &
exec nginx -g 'daemon off;'
