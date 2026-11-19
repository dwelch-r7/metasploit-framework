FROM craftcms/nginx@sha256:695b27dabef25d6d07025b1b13e15a05a2494eb7137b823d7cf81515bb6284b5
USER root
RUN apk add --no-cache python3 bash curl font-dejavu
COPY font-policy.py /tmp/module-target-font-policy.py
RUN python3 /tmp/module-target-font-policy.py && rm /tmp/module-target-font-policy.py
COPY php-fpm-pool.conf /usr/local/etc/php-fpm.d/zz-module-target.conf
USER www-data
WORKDIR /app
ADD --chown=www-data:www-data https://codeload.github.com/craftcms/craft/legacy.tar.gz/8b56598dde738e4de18b710d4a5061fea175099b /tmp/module-target-craft-starter.tar.gz
RUN printf '%s  %s\n' 1dd7bf0e3bc99bda4caaffce3cc30696de32da39945870d3ec921c1cc8ab8190 /tmp/module-target-craft-starter.tar.gz | sha256sum -c - \
    && tar -xzf /tmp/module-target-craft-starter.tar.gz --strip-components=1 -C /app \
    && rm /tmp/module-target-craft-starter.tar.gz
ARG CRAFT_VERSION=4.4.14
COPY --chown=www-data:www-data locks/${CRAFT_VERSION}.json /app/composer.json
COPY --chown=www-data:www-data locks/${CRAFT_VERSION}.lock /app/composer.lock
ENV COMPOSER_CACHE_DIR=/tmp/module-target-composer-cache COMPOSER_MAX_PARALLEL_HTTP=4 XDEBUG_MODE=off
RUN composer install --no-dev --no-interaction --prefer-dist --no-progress --no-scripts
COPY --chown=www-data:www-data native.twig /app/templates/module-target-native.twig
COPY --chown=www-data:www-data native-static.txt /app/web/module-target-native-static.txt
