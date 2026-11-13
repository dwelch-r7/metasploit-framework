ARG ICINGA_IMAGE=icinga/icingaweb2@sha256:c4543a6ced27598f02f4866ba2b82f70bcf7d70b833efc61bd0874fd4e49edc4
FROM ${ICINGA_IMAGE}
USER root
ARG ICINGA_SOURCE_VERSION=
ARG ICINGA_SOURCE_SHA256=
# The oldest boundary releases use complete upstream source archives on the
# same pinned PHP/Apache runtime. Only Apache's URL mapping is configured.
RUN if [ -n "${ICINGA_SOURCE_VERSION}" ]; then \
      php -r 'exit(copy("https://codeload.github.com/Icinga/icingaweb2/tar.gz/refs/tags/v" . $argv[1], "/tmp/icinga-source.tar.gz") ? 0 : 1);' "${ICINGA_SOURCE_VERSION}" && \
      echo "${ICINGA_SOURCE_SHA256}  /tmp/icinga-source.tar.gz" | sha256sum -c - && \
      rm -rf /usr/share/icingaweb2 && mkdir /usr/share/icingaweb2 && \
      tar -xzf /tmp/icinga-source.tar.gz --strip-components=1 -C /usr/share/icingaweb2 && \
      rm /tmp/icinga-source.tar.gz && \
      sed -i 's@^Alias /icingaweb2 .*@Alias / "/usr/share/icingaweb2/public/"@;s@RewriteBase /icingaweb2/@RewriteBase /@;s@/icingaweb2/error_norewrite.html@/error_norewrite.html@' /usr/share/icingaweb2/packages/files/apache/icingaweb2.conf && \
      find /usr/share/icingaweb2 -type f ! -path '*/packages/files/apache/icingaweb2.conf' -print0 | sort -z | xargs -0 sha256sum >/opt/icinga-source-files.sha256; \
    fi
COPY files /lab
COPY start.sh /lab/start.sh
# Only the Apache URL mapping changes in the subpath profile. PHP application
# source and the vulnerable/fixed StaticController remain the official image's.
ARG ICINGA_PREFIX=/
RUN chmod 000 /lab/proof/denied.txt && \
    sed -i "s@Alias / \"/usr/share/icingaweb2/public/\"@Alias ${ICINGA_PREFIX} \"/usr/share/icingaweb2/public/\"@;s@RewriteBase /@RewriteBase ${ICINGA_PREFIX}@" /usr/share/icingaweb2/packages/files/apache/icingaweb2.conf
USER www-data
CMD ["bash", "/lab/start.sh"]
