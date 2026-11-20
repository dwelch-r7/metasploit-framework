FROM php:8.3-cli@sha256:6cb44388b6ffc8c9a35b4cfdf518d0565e0cf9150e479add338b498874d7e971
RUN apt-get update \
    && apt-get install -y --no-install-recommends libonig-dev libzip-dev \
    && docker-php-ext-install -j1 exif bcmath mbstring zip \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:a803b3eae0a0e75e366764345bcb5e30a6d556332750ff964e37adb471ba0350 https://github.com/InvoiceShelf/InvoiceShelf/releases/download/1.3.0/InvoiceShelf.zip /tmp/invoiceshelf.zip
RUN php -r '$archive = new PharData("/tmp/invoiceshelf.zip"); $archive->extractTo("/opt");' \
    && cp /opt/InvoiceShelf/.env.example /opt/InvoiceShelf/.env \
    && rm /tmp/invoiceshelf.zip \
    && chown -R www-data:www-data /opt/InvoiceShelf
COPY setup.php /opt/module-target-setup.php
COPY start.sh /opt/module-target-start.sh
RUN chmod 755 /opt/module-target-start.sh
WORKDIR /opt/InvoiceShelf
USER 33:33
ENTRYPOINT ["/opt/module-target-start.sh"]
