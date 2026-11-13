#!/bin/bash
set -eo pipefail
# The unrelated endpoint uses PHP's unchanged built-in static server.
php -S 0.0.0.0:8081 -t /lab/unrelated >/tmp/icinga-unrelated.log 2>&1 &
echo $! >/tmp/icinga-unrelated.pid
. /etc/apache2/envvars
exec apache2 -DFOREGROUND
