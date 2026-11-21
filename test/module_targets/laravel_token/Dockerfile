FROM vulhub/laravel@sha256:afd50843b9b5dd42418e4abbb2dc0607ff80aa6a68a4722dc4832563c77a7ad5
USER root
WORKDIR /var/www
ADD https://codeload.github.com/laravel/laravel/tar.gz/3f92cf66f53b3b53467497acc0d2a00cbd7b65f0 /tmp/module-target-project.tar.gz
ADD https://getcomposer.org/download/1.10.27/composer.phar /opt/composer.phar
RUN printf '%s  %s\n' 8936265cfa793d6a4afba4835719c4a91eb1e532a546eddf855933fa45b498e4 /tmp/module-target-project.tar.gz 230d28fb29f3c6c07ab2382390bef313e36de17868b2bd23b2e070554cae23d2 /opt/composer.phar | sha256sum -c - \
    && find /var/www -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + \
    && tar -xzf /tmp/module-target-project.tar.gz --strip-components=1 -C /var/www \
    && rm /tmp/module-target-project.tar.gz
COPY composer.json composer.lock /var/www/
ENV COMPOSER_ALLOW_SUPERUSER=1 COMPOSER_MAX_PARALLEL_HTTP=4 COMPOSER_PROCESS_TIMEOUT=90
RUN php -d memory_limit=512M /opt/composer.phar install --no-interaction --prefer-dist --no-progress --no-scripts --no-plugins \
    && printf "\nRoute::post('/', function () { return view('welcome'); });\n" >> routes/web.php
COPY apache.conf /etc/apache2/sites-enabled/000-default.conf
COPY setup.php /opt/module-target-setup.php
COPY native.php /opt/module-target-native.php
COPY vendor.json /opt/module-target-vendor.json
COPY start.sh /opt/module-target-start.sh
CMD ["sh", "/opt/module-target-start.sh"]
