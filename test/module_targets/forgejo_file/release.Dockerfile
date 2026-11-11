# The 16.x registry indexes currently reference missing platform manifests.
# Keep the vendor runtime and install the genuine, checksum-pinned release binary.
FROM codeberg.org/forgejo/forgejo:15.0.5@sha256:179e4daa2b14964285bf77b16108c245a7e4f18a18081f129534967f464fd89d
ARG FORGEJO_VERSION
ARG FORGEJO_COMMIT
ARG FORGEJO_XZ_SHA256
ARG FORGEJO_BINARY_SHA256
RUN curl --fail --silent --show-error --location \
      "https://codeberg.org/forgejo/forgejo/releases/download/v${FORGEJO_VERSION}/forgejo-${FORGEJO_VERSION}-linux-amd64.xz" \
      --output /tmp/forgejo.xz \
    && printf '%s  %s\n' "$FORGEJO_XZ_SHA256" /tmp/forgejo.xz | sha256sum -c - \
    && busybox unxz -c /tmp/forgejo.xz > /app/gitea/gitea \
    && printf '%s  %s\n' "$FORGEJO_BINARY_SHA256" /app/gitea/gitea | sha256sum -c - \
    && chmod 755 /app/gitea/gitea \
    && rm /tmp/forgejo.xz
LABEL org.opencontainers.image.version="${FORGEJO_VERSION}" \
      org.opencontainers.image.revision="${FORGEJO_COMMIT}" \
      org.metasploit.module_target.forgejo.binary_sha256="${FORGEJO_BINARY_SHA256}"
