FROM wordpress:6.8.3-php8.3-apache@sha256:30bff39330d1693b0ce13d32fc9b7bb67193064f040b7d60d3494e136fa599d4
ARG OSTICKET_RELEASE=1.18.2
ARG OSTICKET_SHA256=9e523ca5bec6324166bdb60fe2bce26c37fc6eefb256e281ad95f70138486bc6
RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:${OSTICKET_SHA256} https://github.com/osTicket/osTicket/releases/download/v${OSTICKET_RELEASE}/osTicket-v${OSTICKET_RELEASE}.zip /opt/osticket/release.zip
RUN php -r '$z=new ZipArchive();if($z->open("/opt/osticket/release.zip")!==true){exit(1);}if(!$z->extractTo("/opt/osticket/source")){exit(1);}$z->close();' && rm /opt/osticket/release.zip
RUN printf 'sendmail_path=/bin/true\ndate.timezone=UTC\n' > /usr/local/etc/php/conf.d/module-target.ini && printf 'ServerName localhost\nStartServers 1\nMinSpareServers 1\nMaxSpareServers 2\nMaxRequestWorkers 4\n' > /etc/apache2/conf-enabled/module-target.conf
COPY entrypoint.sh /opt/osticket/entrypoint.sh
RUN chmod 755 /opt/osticket/entrypoint.sh
ENTRYPOINT ["/opt/osticket/entrypoint.sh"]
CMD ["apache2-foreground"]
