ARG PRETALX_IMAGE=pretalx/standalone@sha256:ad44382132798d83402755d9ffad9b2f24c3d2bdddc40ed6f28cdfb3ebc14f1c
FROM ${PRETALX_IMAGE}
COPY --chown=pretalxuser:pretalxuser . /execution
ENV PRETALX_CONFIG_FILE=/lab/pretalx.cfg PRETALX_DATA_DIR=/data DJANGO_SETTINGS_MODULE=pretalx.settings HOME=/pretalx
WORKDIR /pretalx/src
ENTRYPOINT ["/bin/bash", "/execution/start.sh"]
