FROM wordpress:6.8.3-php8.3-apache@sha256:30bff39330d1693b0ce13d32fc9b7bb67193064f040b7d60d3494e136fa599d4 AS source
ARG DRUPAL_VERSION
ARG DRUPAL_SHA256
RUN curl --fail --location --silent --show-error "https://ftp.drupal.org/files/projects/drupal-${DRUPAL_VERSION}.tar.gz" -o /tmp/drupal.tar.gz \
    && printf '%s  /tmp/drupal.tar.gz\n' "${DRUPAL_SHA256}" | sha256sum -c - \
    && mkdir /opt/drupal \
    && tar -xzf /tmp/drupal.tar.gz --strip-components=1 -C /opt/drupal

FROM php:5.6.40-apache@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d
COPY --from=source /usr/share/keyrings/debian-archive-keyring.gpg /usr/share/keyrings/module-target-debian.gpg
RUN printf '%s\n' 'deb [signed-by=/usr/share/keyrings/module-target-debian.gpg] http://archive.debian.org/debian stretch main' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends libpng-dev=1.6.28-1+deb9u1 \
    && docker-php-ext-install -j2 pdo_mysql gd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=source /opt/drupal/ /opt/drupal/
COPY seed.php inspect.php /opt/module-target/
COPY fixture.ini /usr/local/etc/php/conf.d/module-target.ini
COPY start.sh /usr/local/bin/module-target-start
RUN chmod 755 /usr/local/bin/module-target-start
WORKDIR /var/www/html
ENTRYPOINT ["module-target-start"]
