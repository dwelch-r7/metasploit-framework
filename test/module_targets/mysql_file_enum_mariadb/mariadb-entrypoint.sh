#!/bin/bash
set -eu
# The vendor server validates secure_file_priv before initializing its database.
mkdir -p /var/lib/mysql-files
chown mysql:mysql /var/lib/mysql-files
exec docker-entrypoint.sh "$@"
