#!/bin/sh
set -eu
php craft install/craft --interactive=0 --username=admin \
  --password=module-target-craft-admin --email=admin@example.test \
  --siteName='Module target Craft' --siteUrl=http://localhost:8080/ --language=en
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisor.conf
