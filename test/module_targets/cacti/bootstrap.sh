#!/bin/bash
set -euo pipefail
cd /var/www/html
mysql --host=db --user=root --password=root cacti < cacti.sql
chown -R www-data:www-data /var/www/html
php cli/install_cacti.php --accept-eula --install --path=php_binary:/usr/local/bin/php --path=rrdtool:/usr/bin/rrdtool --automationmode=0
chown -R www-data:www-data /var/www/html
exec docker-php-entrypoint apache2-foreground
