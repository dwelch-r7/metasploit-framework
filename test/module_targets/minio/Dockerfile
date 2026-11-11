ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}
ARG APP_UID
ARG APP_GID
COPY --chown=${APP_UID}:${APP_GID} home/ /home/minio/
COPY --chown=${APP_UID}:${APP_GID} drive/ /data1/
COPY --chown=${APP_UID}:${APP_GID} drive/ /data2/
COPY mc /usr/local/bin/mc
COPY minio /usr/local/bin/minio
COPY provenance.json /usr/share/minio-module-target-provenance.json
USER ${APP_UID}:${APP_GID}
ENV HOME=/home/minio
WORKDIR /home/minio
ENTRYPOINT ["/usr/local/bin/minio"]
