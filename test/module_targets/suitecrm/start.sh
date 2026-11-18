#!/bin/bash
set -eu
cd /var/www/html
for attempt in $(seq 1 90); do
 if php -r '$db=@new mysqli("db","root","module-suite-db-root","suitecrm");exit($db->connect_errno?1:0);' 2>/dev/null; then break; fi
 if [[ "$attempt" == 90 ]]; then exit 2; fi
 sleep 1
done
if [[ ! -f /opt/module-target/installed ]]; then
 cp /opt/module-target/config_si.php config_si.php
 chown -R www-data:www-data /var/www/html
 su -s /bin/bash www-data -c 'php /opt/module-target/install.php' > /tmp/module-target-install.log 2>&1
 test -s config.php
 php -r 'require "config.php";exit(empty($sugar_config["installer_locked"])?1:0);'
 su -s /bin/bash www-data -c 'php /opt/module-target/seed.php' > /tmp/module-target-seed.json 2> /tmp/module-target-seed.stderr
 if [[ ${MODULE_SUITECRM_NAMES:-0} == 1 ]]; then
  su -s /bin/bash www-data -c 'php /opt/module-target/names.php' > /tmp/module-target-names.json 2> /tmp/module-target-names.stderr
 fi
 rm -- config_si.php
 touch /opt/module-target/installed
fi
exec apache2-foreground
