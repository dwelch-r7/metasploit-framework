ARG JOOMLA_IMAGE=joomla:4.2.7-php8.1-apache@sha256:2a32bb358d95627f7c9ef2eb834e61746b4270c367046eea3dbe802d6f16cbac
FROM ${JOOMLA_IMAGE}

ARG LAB_PREFIX=""
ENV LAB_PREFIX=${LAB_PREFIX}
RUN mkdir -p "/var/www/html${LAB_PREFIX}" \
    && cp -a /usr/src/joomla/. "/var/www/html${LAB_PREFIX}/" \
    && chown -R www-data:www-data /var/www/html
COPY seed.php inspect.php accounts.json start.sh hidden.conf /opt/module-target/
RUN chmod 755 /opt/module-target/start.sh
ENTRYPOINT ["/opt/module-target/start.sh"]
