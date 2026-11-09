FROM wordpress:6.8.3-php8.3-apache@sha256:30bff39330d1693b0ce13d32fc9b7bb67193064f040b7d60d3494e136fa599d4

RUN mv /usr/local/bin/apache2-foreground /usr/local/bin/module-target-apache
COPY apache2-foreground /usr/local/bin/apache2-foreground
COPY seed.php inspect.php /opt/module-target/
RUN chmod 755 /usr/local/bin/apache2-foreground
