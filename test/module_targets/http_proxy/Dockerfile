FROM httpd:2.4.62@sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e

COPY index.html /usr/local/apache2/htdocs/index.html
COPY open.conf denied.conf destination.conf /usr/local/apache2/conf/extra/
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=destination \
    -addext 'subjectAltName=DNS:destination' \
    -keyout /usr/local/apache2/conf/module-target.key \
    -out /usr/local/apache2/conf/module-target.crt \
    && chmod 600 /usr/local/apache2/conf/module-target.key
