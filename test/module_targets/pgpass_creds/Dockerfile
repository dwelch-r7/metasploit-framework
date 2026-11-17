FROM postgres:16@sha256:933463a6c8eba2b9f5cd414138738cd8d5519cd2c471214c222652f547a66a32

ARG PYTHON_PACKAGE=python3=3.13.5-1
RUN apt-get update -qq && apt-get install -y --no-install-recommends ${PYTHON_PACKAGE} \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1001 --create-home --shell /bin/bash labuser \
    && useradd --uid 1002 --create-home --shell /bin/bash otheruser \
    && mkdir -p /opt/module-target-artifacts

COPY init.sql /docker-entrypoint-initdb.d/pgpass-target.sql
