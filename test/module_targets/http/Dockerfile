FROM httpd:2.4.62@sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e
COPY htdocs/ /usr/local/apache2/htdocs/
COPY module-target.conf /usr/local/apache2/conf/extra/module-target.conf
RUN printf '\nInclude conf/extra/module-target.conf\n' >> /usr/local/apache2/conf/httpd.conf \
    && htpasswd -bc /usr/local/apache2/conf/module-target.htpasswd module-test-user module-test-password
