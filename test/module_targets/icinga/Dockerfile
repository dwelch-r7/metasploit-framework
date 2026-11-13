ARG ICINGA_IMAGE=icinga/icingaweb2@sha256:c4543a6ced27598f02f4866ba2b82f70bcf7d70b833efc61bd0874fd4e49edc4
FROM ${ICINGA_IMAGE}
USER root
COPY files /lab
COPY start.sh /lab/start.sh
# Only the Apache URL mapping changes in the subpath profile. PHP application
# source and the vulnerable/fixed StaticController remain the official image's.
ARG ICINGA_PREFIX=/
RUN chmod 000 /lab/proof/denied.txt && \
    sed -i "s@Alias / \"/usr/share/icingaweb2/public/\"@Alias ${ICINGA_PREFIX} \"/usr/share/icingaweb2/public/\"@;s@RewriteBase /@RewriteBase ${ICINGA_PREFIX}@" /usr/share/icingaweb2/packages/files/apache/icingaweb2.conf
USER www-data
CMD ["bash", "/lab/start.sh"]
