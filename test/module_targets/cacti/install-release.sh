#!/bin/bash
set -euo pipefail
# Cacti1.2.23 requires these extensions; keep the earlier-release runtime intact.
# Reuse the dated Bullseye repository setup used by the SuiteCRM fixture.
if [ "${CACTI_INSTALL_INTL_PCNTL:-false}" = true ]; then
    snapshot=20230301T000000Z
    printf 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/%s/ bullseye main\n' "$snapshot" > /etc/apt/sources.list
    apt-get -o Acquire::Retries=1 -o Acquire::https::Timeout=30 update
    apt-get -o Acquire::Retries=1 -o Acquire::https::Timeout=30 install -y --no-install-recommends libicu-dev
    docker-php-ext-install -j1 intl pcntl
    php -r 'exit(extension_loaded("intl") && extension_loaded("pcntl") ? 0 : 1);'
    dpkg-query -W > /opt/cacti-runtime-packages.tsv
    rm -rf /var/lib/apt/lists/*
fi
# Use a complete pinned upstream tree rather than patching vulnerability checks.
wget --timeout=30 --tries=1 -q -O /tmp/cacti.tar.gz "https://codeload.github.com/Cacti/cacti/tar.gz/${CACTI_REVISION}"
printf '%s  /tmp/cacti.tar.gz\n' "$CACTI_ARCHIVE_SHA256" | sha256sum -c -
cp /var/www/html/include/config.php /tmp/cacti-database-config.php
find /var/www/html -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
tar -xzf /tmp/cacti.tar.gz -C /var/www/html --strip-components=1
cp /tmp/cacti-database-config.php /var/www/html/include/config.php
rm -f /tmp/cacti.tar.gz /tmp/cacti-database-config.php
