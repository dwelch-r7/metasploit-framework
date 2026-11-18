FROM php:7.4.33-apache-bullseye@sha256:18b3497ee7f2099a90b66c23a0bc3d5261b12bab367263e1b40e9b004c39e882
RUN printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20230301T000000Z/ bullseye main' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20230301T000000Z/ bullseye-security main' > /etc/apt/sources.list \
 && apt-get update && apt-get install -y --no-install-recommends \
    libfreetype6-dev libjpeg62-turbo-dev libpng-dev libc-client2007e-dev \
    libkrb5-dev libicu-dev libzip-dev libonig-dev libxml2-dev unzip python3 \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-configure imap --with-kerberos --with-imap-ssl \
 && docker-php-ext-install -j1 gd imap mysqli pdo_mysql mbstring soap intl zip \
 && a2enmod rewrite \
 && printf '%s\n' 'memory_limit=512M' 'max_execution_time=120' 'date.timezone=UTC' > /usr/local/etc/php/conf.d/module-target.ini \
 && dpkg-query -W -f='${binary:Package}\t${Version}\n' > /opt/module-target-packages.tsv \
 && rm -rf /var/lib/apt/lists/*

RUN docker-php-ext-install -j1 opcache \
 && php --version | grep -q 'Zend OPcache'
RUN printf '%s\n' 'opcache.enable=1' 'opcache.memory_consumption=128' 'opcache.max_accelerated_files=30000' > /usr/local/etc/php/conf.d/module-target-opcache.ini
RUN printf '%s\n' 'display_errors=Off' 'log_errors=On' 'error_log=/dev/stderr' > /usr/local/etc/php/conf.d/module-target-errors.ini
ARG SUITECRM_VERSION=7.12.5
ARG SUITECRM_SHA256=d8bfa74a7d89f4e05b8f70f7409b9928bdbd690803453049e7b3c645e6a7b483
RUN curl --fail --location --silent --show-error "https://github.com/SuiteCRM/SuiteCRM/releases/download/v${SUITECRM_VERSION}/SuiteCRM-${SUITECRM_VERSION}.zip" -o /tmp/suitecrm.zip \
 && echo "${SUITECRM_SHA256}  /tmp/suitecrm.zip" | sha256sum -c - \
 && unzip -q /tmp/suitecrm.zip -d /opt/release \
 && cp -a /opt/release/SuiteCRM-${SUITECRM_VERSION}/. /var/www/html/ \
 && rm -rf /opt/release /tmp/suitecrm.zip
COPY config_si.php install.php seed.php names.php names.json start.sh control.php /opt/module-target/
CMD ["bash", "/opt/module-target/start.sh"]
