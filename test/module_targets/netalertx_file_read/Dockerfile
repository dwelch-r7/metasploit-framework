ARG NETALERTX_IMAGE=jokobsk/netalertx@sha256:c9f67ae8361d13dc0599b0a05a3c186c6fe46a0ae4039c34b45496550e5f52b7
FROM ${NETALERTX_IMAGE}
COPY bootstrap.py start-web.sh /opt/module-target-netalertx/
ENTRYPOINT ["/bin/sh", "/opt/module-target-netalertx/start-web.sh"]
