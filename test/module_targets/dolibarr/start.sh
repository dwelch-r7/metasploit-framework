#!/bin/sh
set -eu
if [ "${1:-}" = health ]; then
  exec php -r '$url="http://127.0.0.1:8080".getenv("DOLIBARR_PREFIX")."/";exit(@file_get_contents($url)===false ? 1 : 0);'
fi
mkdir -p /tmp/dolibarr/documents /tmp/dolibarr/sessions /tmp/dolibarr/www
cp /lab/conf.php /opt/dolibarr/htdocs/conf/conf.php
chmod 600 /opt/dolibarr/htdocs/conf/conf.php
app_php() {
  php -d extension=/runtime/mysqli.so -d date.timezone=UTC -d memory_limit=160M -d display_errors=0 -d log_errors=1 "$@"
}
cd /opt/dolibarr/htdocs/install
app_php step2.php set en_US > /tmp/dolibarr/step2.html 2> /tmp/dolibarr/step2.stderr
app_php step5.php '' '' en_US set moduleadmin 'ModuleAdminPassword1!' 'ModuleAdminPassword1!' 1 > /tmp/dolibarr/step5.html 2> /tmp/dolibarr/step5.stderr
app_php /lab/state.php seed > /tmp/dolibarr/seed.json 2> /tmp/dolibarr/seed.stderr
chmod 444 /opt/dolibarr/htdocs/conf/conf.php
chmod 555 /opt/dolibarr/htdocs/conf
if [ -n "${DOLIBARR_PREFIX}" ]; then
  ln -s /opt/dolibarr/htdocs "/tmp/dolibarr/www${DOLIBARR_PREFIX}"
  document_root=/tmp/dolibarr/www
else
  document_root=/opt/dolibarr/htdocs
fi
exec php -d extension=/runtime/mysqli.so -d date.timezone=UTC -d memory_limit=128M -d display_errors=0 -d log_errors=1 -d session.save_path=/tmp/dolibarr/sessions -S 0.0.0.0:8080 -t "$document_root"
