FROM wordpress:5.2.4-php7.3-apache@sha256:83a8d86d5266cf2ff24715e248226b60b3a3f8e8d4a27fcc7ed4f33a4d09e468
COPY start.sh /opt/module-target/start.sh
RUN chmod 755 /opt/module-target/start.sh
ENTRYPOINT ["/opt/module-target/start.sh"]
CMD ["apache2-foreground"]
