FROM owncloud/server@sha256:00dcd8fb95abc507bc920e859c50f272dfd12b2ccfef63930c0006ada03fb064

# Install the complete fixed app from the pinned official 10.13.1 image's
# application layer. This avoids downloading a second PHP/Apache runtime.
# The resulting core/runtime is still 10.12.1; only graphapi becomes 0.3.1.
RUN set -eu; \
    token="$(curl -fsSL 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:owncloud/server:pull' | jq -r .token)"; \
    curl -fsSL -H "Authorization: Bearer ${token}" \
      'https://registry-1.docker.io/v2/owncloud/server/blobs/sha256:81ee684122331ba159621715b217cf63ade13ffce7bf0cc45979bef57bda8dff' \
      -o /tmp/graphapi-vendor-layer.tar.gz; \
    printf '%s  %s\n' '81ee684122331ba159621715b217cf63ade13ffce7bf0cc45979bef57bda8dff' /tmp/graphapi-vendor-layer.tar.gz | sha256sum -c -; \
    rm -rf /var/www/owncloud/apps/graphapi; \
    tar -xzf /tmp/graphapi-vendor-layer.tar.gz -C / var/www/owncloud/apps/graphapi; \
    test ! -e /var/www/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php; \
    rm /tmp/graphapi-vendor-layer.tar.gz

LABEL org.metasploit.module_target.owncloud.core_version="10.12.1" \
      org.metasploit.module_target.owncloud.graphapi_version="0.3.1" \
      org.metasploit.module_target.owncloud.vendor_manifest="sha256:73bcb7352f6c9085d78d3724bf30d4b2ff6ed9137c9be583e75b4707483ad784"
