FROM httpd:2.4.62@sha256:4c7788695c832bf415a662dfb5160f1895e65fc65c025e85f436ee2c9e7d7f3e

COPY module-target.conf /usr/local/apache2/conf/extra/module-target-webdav.conf
RUN sed -i 's/^#LoadModule dav_module/LoadModule dav_module/; s/^#LoadModule dav_fs_module/LoadModule dav_fs_module/' /usr/local/apache2/conf/httpd.conf \
    && printf '\nInclude conf/extra/module-target-webdav.conf\n' >> /usr/local/apache2/conf/httpd.conf \
    && mkdir -p /usr/local/apache2/var /usr/local/apache2/htdocs/dav /usr/local/apache2/htdocs/auth /usr/local/apache2/htdocs/readonly /usr/local/apache2/htdocs/plain \
    && printf 'module-target-existing-content\n' > /usr/local/apache2/htdocs/dav/existing.txt \
    && cp /usr/local/apache2/htdocs/dav/existing.txt /usr/local/apache2/htdocs/auth/existing.txt \
    && cp /usr/local/apache2/htdocs/dav/existing.txt /usr/local/apache2/htdocs/readonly/existing.txt \
    && cp /usr/local/apache2/htdocs/dav/existing.txt /usr/local/apache2/htdocs/plain/existing.txt \
    && dav_user=$(awk '$1 == "User" { print $2 }' /usr/local/apache2/conf/httpd.conf) \
    && dav_group=$(awk '$1 == "Group" { print $2 }' /usr/local/apache2/conf/httpd.conf) \
    && chown -R "$dav_user:$dav_group" /usr/local/apache2/var /usr/local/apache2/htdocs \
    && htpasswd -bc /usr/local/apache2/conf/module-target-webdav.htpasswd lab-dav-user lab-dav-password
