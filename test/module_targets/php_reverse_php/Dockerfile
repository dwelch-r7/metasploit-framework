FROM wordpress:6.8.3-php8.3-apache@sha256:30bff39330d1693b0ce13d32fc9b7bb67193064f040b7d60d3494e136fa599d4

# This exact base bundles matching PHP source and the existing build tools.
# Only sockets is compiled; no packages or application dependencies are added.
RUN set -eux; \
    test "$(php-config --version)" = "8.3.28"; \
    sha256sum /usr/src/php.tar.xz; \
    docker-php-source extract; \
    grep PHP_VERSION /usr/src/php/main/php_version.h; \
    sha256sum /usr/src/php/ext/sockets/*.c /usr/src/php/ext/sockets/config.m4; \
    docker-php-ext-install -j1 sockets; \
    php --ri sockets; \
    sha256sum /usr/local/lib/php/extensions/*/sockets.so

COPY controller.php exception_probe.php cases.json /probe/
COPY bin/0 /probe/bin/0
RUN chmod 0555 /probe/bin/0
