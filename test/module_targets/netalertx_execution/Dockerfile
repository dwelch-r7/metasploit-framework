ARG NETALERTX_IMAGE=jokobsk/netalertx@sha256:c9f67ae8361d13dc0599b0a05a3c186c6fe46a0ae4039c34b45496550e5f52b7
FROM ${NETALERTX_IMAGE}
COPY configure.py start.sh /opt/module-target-execution/
ENTRYPOINT ["/bin/sh", "/opt/module-target-execution/start.sh"]
