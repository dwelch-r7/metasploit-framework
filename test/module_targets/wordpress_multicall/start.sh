#!/bin/sh
set -eu
php /opt/module-target/seed.php
exec apache2-foreground
