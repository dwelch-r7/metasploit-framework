ARG HTTPD_IMAGE=httpd:2.4.49@sha256:dcba0d12e2362fb0c50ec524ae8aa1cca4a4ba7216617a57e7bbca20767e79cc
FROM ${HTTPD_IMAGE}
ARG ROOT_ACCESS=granted
# These intentionally permissive rules recreate the advisory's prerequisite:
# https://httpd.apache.org/security/vulnerabilities_24.html#CVE-2021-41773
RUN sed -i "s/Require all denied/Require all ${ROOT_ACCESS}/; s/#LoadModule cgid_module/LoadModule cgid_module/" /usr/local/apache2/conf/httpd.conf \
    && printf '\nServerName module-target.local\nAlias /files/ /usr/local/apache2/htdocs/\n' >> /usr/local/apache2/conf/httpd.conf \
    && printf 'module-target-apache-normalize\n' > /usr/local/apache2/htdocs/index.html \
    && printf 'module-target-traversal-secret\n' > /opt/module-target-secret.txt
