# Immutable Temurin 17 JDK/Jammy reference; the local tag may be absent.
FROM eclipse-temurin@sha256:057a0daec60e87c96571bf5c9c7792065bcb19e804d584cd37d4144038a35717
WORKDIR /lab
COPY settings.sh build.sh start.sh native.sh health.sh /lab/
COPY source /lab/source
RUN ["bash", "/lab/build.sh"]
CMD ["bash", "/lab/start.sh"]
