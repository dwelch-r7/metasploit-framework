#!/bin/sh
set -eu
if [ "${1:-}" = health ]; then
  test -s /tmp/module-target-ready
  exec php -r '$url="http://127.0.0.1".getenv("CONCRETE_PREFIX")."/";exit(@file_get_contents($url)===false?1:0);'
fi
php /lab/verify.php > /tmp/module-target-source.json
if [ -n "${CONCRETE_PREFIX}" ]; then
  mkdir -p /tmp/module-target-site
  ln -s /app "/tmp/module-target-site${CONCRETE_PREFIX}"
  sed -i "s@root /app;@root /tmp/module-target-site;@;s@/index.php?@${CONCRETE_PREFIX}/index.php?@" /etc/nginx/sites-available/default
fi
ccm-service start db web
sudo -u www-data php /lab/state.php seed > /tmp/module-target-seed-output.json
printf 'ready\n' > /tmp/module-target-ready
cleanup() { ccm-service stop db web; exit; }
trap cleanup TERM INT
sleep infinity &
wait "$!"
