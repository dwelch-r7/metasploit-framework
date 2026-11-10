ARG GRAFANA_IMAGE=grafana/grafana:11.0.0-ubuntu@sha256:dcd3ae78713958a862732c3608d32c03f0c279c35a2032d74b80b12c5cdc47b8
FROM ${GRAFANA_IMAGE}
USER root
# This is a measured official-release SHA256, not a publisher-signature claim.
ADD --checksum=sha256:461d949dd4e8e03949dddf65398426adeaa67b459c2fca1316208bcac36aaac7 https://github.com/duckdb/duckdb/releases/download/v1.1.2/duckdb_cli-linux-amd64.zip /tmp/duckdb.zip
RUN apt-get update \
    && apt-get install --no-install-recommends -y unzip libstdc++6 \
    && unzip -p /tmp/duckdb.zip duckdb > /usr/local/bin/duckdb \
    && chmod 0755 /usr/local/bin/duckdb \
    && rm /tmp/duckdb.zip \
    && rm -rf /var/lib/apt/lists/*
RUN install -d -m 0755 -o 472 -g 0 /usr/share/grafana/.duckdb
ENV HOME=/usr/share/grafana
USER 472
# Use the same named genuine repository as the module, retaining signature checks.
# Signed loading and the actual cache/platform remain native prerequisites.
RUN /usr/local/bin/duckdb '' -c 'INSTALL shellfs FROM community;' \
    && /usr/local/bin/duckdb '' -c "LOAD shellfs; SELECT current_setting('allow_unsigned_extensions');"
# Pin the same signed extension bytes observed in the preserved native gate.
RUN printf '%s  %s\n' \
    '18f2493eddd76123a0f4004d38b43db33c7c145a9d618c952d54d69dfa15f175' \
    '/usr/share/grafana/.duckdb/extensions/v1.1.2/linux_amd64_gcc4/shellfs.duckdb_extension' \
    | sha256sum --check -
