ARG GOGS_IMAGE=gogs/gogs:0.14.2@sha256:c8a080c3ddd753436c5671f004536ef9fd84f52e17e1c4467e3de1d43e1073b3
FROM ${GOGS_IMAGE}
COPY start.sh /opt/module-target-gogs-start.sh
COPY accounts.tsv /opt/module-target-gogs-accounts.tsv
CMD ["/bin/sh", "/opt/module-target-gogs-start.sh"]
