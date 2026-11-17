#!/bin/sh
set -eu
# Append only this component's feature flag to the inherited core configuration.
WORDPRESS_CONFIG_EXTRA="${WORDPRESS_CONFIG_EXTRA}
require '/opt/module-target/rce-config.php';"
export WORDPRESS_CONFIG_EXTRA
exec /bin/sh /opt/module-target/core-entrypoint.sh "$@"
