FROM wordpress:6.8.3-php8.3-apache@sha256:30bff39330d1693b0ce13d32fc9b7bb67193064f040b7d60d3494e136fa599d4 AS source
ARG WORDPRESS_VERSION
ARG WORDPRESS_SHA256
RUN curl --fail --location --silent --show-error "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz" -o /tmp/wordpress.tar.gz \
    && printf '%s  /tmp/wordpress.tar.gz\n' "${WORDPRESS_SHA256}" | sha256sum -c - \
    && mkdir /opt/wordpress \
    && tar -xzf /tmp/wordpress.tar.gz --strip-components=1 -C /opt/wordpress

FROM php:5.6.40-apache@sha256:0a40fd273961b99d8afe69a61a68c73c04bc0caa9de384d3b2dd9e7986eec86d
RUN docker-php-ext-configure mysqli --with-mysqli=mysqlnd \
    && docker-php-ext-install mysqli
WORKDIR /var/www/html
COPY --from=source /opt/wordpress/ /var/www/html/
COPY wp-config.php /var/www/html/wp-config.php
COPY accounts.json prep.php seed.php /opt/module-target/
COPY fixture.ini /usr/local/etc/php/conf.d/module-target.ini
COPY start.sh /usr/local/bin/module-target-start
RUN chmod 755 /usr/local/bin/module-target-start \
    && chown -R www-data:www-data /var/www/html
ENTRYPOINT ["module-target-start"]
