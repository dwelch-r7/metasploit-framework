FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11 AS builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl libcrypt-dev && rm -rf /var/lib/apt/lists/*

ARG PROFTPD_VERSION=1.3.5
RUN set -eux; \
    case "$PROFTPD_VERSION" in \
      1.3.5) source_url=https://archive.debian.org/debian/pool/main/p/proftpd-dfsg/proftpd-dfsg_1.3.5.orig.tar.gz; \
        digest=8ac3104658b9ce7cf308d9abc3d4b38168f0a7fdc25c1d88c565dedf319ba287 ;; \
      1.3.5a) source_url=https://api.github.com/repos/proftpd/proftpd/tarball/379bdb0d413f9489768c29c3a36e7bc854c85395; \
        digest=4f2c6fe7fde1954f5cbf76c826a67704d56f18208cbf5792fb4dd11a788290d0 ;; \
      *) exit 2 ;; \
    esac; \
    curl --fail --location --retry 2 --output /tmp/source.tar.gz "$source_url"; \
    echo "$digest  /tmp/source.tar.gz" | sha256sum -c -; \
    mkdir /tmp/source; tar -xzf /tmp/source.tar.gz --strip-components=1 -C /tmp/source; \
    cd /tmp/source; \
    ./configure --prefix=/usr/local --sysconfdir=/etc/proftpd --with-modules=mod_copy --disable-auth-pam --disable-nls; \
    make -j1; make install; \
    mkdir -p /usr/local/share/module-target; \
    printf '%s\n%s\n' "$PROFTPD_VERSION" "$digest" > /usr/local/share/module-target/proftpd-source; \
    sha256sum contrib/mod_copy.c >> /usr/local/share/module-target/proftpd-source; \
    /usr/local/sbin/proftpd -V > /usr/local/share/module-target/proftpd-build; \
    /usr/local/sbin/proftpd -l > /usr/local/share/module-target/proftpd-modules

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libcrypt1 netcat-traditional openssl perl php-cli python3 procps iproute2 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/sbin/proftpd /usr/local/sbin/proftpd
COPY --from=builder /usr/local/share/module-target /usr/local/share/module-target
RUN mkdir -p /etc/proftpd /var/www/html/lab /opt/module-target-proftpd && \
    password_hash="$(openssl passwd -6 -salt module-target module-target-password)" && \
    printf 'ftplab:%s:33:33:Module target:/var/www/html:/bin/sh\n' "$password_hash" > /etc/proftpd/users && \
    printf 'www-data:x:33:ftplab\n' > /etc/proftpd/groups && \
    chmod 0600 /etc/proftpd/users /etc/proftpd/groups && \
    printf 'module-target-proftpd-foreign\n' > /var/www/html/foreign.txt && \
    chmod 0444 /var/www/html/foreign.txt && \
    printf '<?php echo "module-target-proftpd-ready\\n";\n' > /var/www/html/health.php && \
    printf '<?php passthru($_GET["cmd"]);\n' > /var/www/html/native.php && \
    dpkg-query -W -f='${Package}=${Version}\n' > /usr/local/share/module-target/packages
COPY proftpd.conf serve.py /opt/module-target-proftpd/
CMD ["python3", "-B", "/opt/module-target-proftpd/serve.py"]
