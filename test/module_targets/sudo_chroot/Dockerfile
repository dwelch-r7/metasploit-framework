FROM ubuntu@sha256:9c7f200c07e3d4a03e7249d2c16bf66a51120fb876aa2242cf31451412543289

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl libpam0g-dev libselinux1-dev zlib1g-dev \
    pkg-config libssl-dev python3 procps iproute2 util-linux && \
    rm -rf /var/lib/apt/lists/*

ARG SUDO_VERSION=1.9.16p2
# Official release assets; the fixed digest is also published by GitHub.
# Both digests are recorded by Buildroot's sudo security update.
RUN set -eux; \
    case "$SUDO_VERSION" in \
      1.9.16p2) digest=976aa56d3e3b2a75593307864288addb748c9c136e25d95a9cc699aafa77239c ;; \
      1.9.17p1) digest=ff607ea717072197738a78f778692cd6df9a7e3e404565f51de063ca27455d32 ;; \
      *) exit 2 ;; \
    esac; \
    curl --fail --location --retry 2 --output /tmp/sudo.tar.gz \
      "https://github.com/sudo-project/sudo/releases/download/v${SUDO_VERSION}/sudo-${SUDO_VERSION}.tar.gz"; \
    echo "$digest  /tmp/sudo.tar.gz" | sha256sum -c -; \
    mkdir /tmp/sudo-source; \
    tar -xzf /tmp/sudo.tar.gz --strip-components=1 -C /tmp/sudo-source; \
    cd /tmp/sudo-source; \
    ./configure --prefix=/usr/local --sysconfdir=/etc --disable-gcrypt --disable-nls; \
    make -j1; \
    make install; \
    mkdir -p /usr/local/share/module-target; \
    printf '%s\n%s\n' "$SUDO_VERSION" "$digest" > /usr/local/share/module-target/sudo-source; \
    dpkg-query -W -f='${Package}=${Version}\n' > /usr/local/share/module-target/packages; \
    rm -rf /tmp/sudo-source /tmp/sudo.tar.gz

RUN useradd --create-home --uid 1001 --shell /bin/bash lab && \
    printf 'foreign-sudo-chroot-fixture\n' > /home/lab/foreign && \
    chmod 0444 /home/lab/foreign && \
    test "$(stat -c '%u:%a' /usr/local/bin/sudo)" = 0:4755

USER 1001:1001
WORKDIR /home/lab
CMD ["sleep", "infinity"]
