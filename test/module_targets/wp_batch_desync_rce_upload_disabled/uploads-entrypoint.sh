#!/bin/sh
set -eu
# Docker exec does not inherit environment changes made by PID 1. Use the
# official image's _FILE support so HTTP and native PHP read identical config.
: "${WORDPRESS_CONFIG_EXTRA_FILE:?Missing persistent config path}"
printf '%s\n%s\n' "$WORDPRESS_CONFIG_EXTRA" "require '/opt/module-target/rce-config.php';" > "$WORDPRESS_CONFIG_EXTRA_FILE"
exec /bin/sh /opt/module-target/core-entrypoint.sh "$@"
