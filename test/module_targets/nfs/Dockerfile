FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN sed -i 's,archive.ubuntu.com,security.ubuntu.com,g' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential flex bison libtirpc-dev pkg-config rpcbind netbase nfs-common libnfs-utils iproute2 python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ADD https://github.com/unfs3/unfs3/releases/download/unfs3-0.11.0/unfs3-0.11.0.tar.gz /tmp/unfs3.tar.gz
RUN printf '%s  /tmp/unfs3.tar.gz\n' 42ef63cd949b65a4ead30bee269703059a8c4269bef6aa1533215ad1c2a26d6f | sha256sum --check - \
    && mkdir /usr/src/unfs3 \
    && tar -xzf /tmp/unfs3.tar.gz --strip-components=1 -C /usr/src/unfs3 \
    && cd /usr/src/unfs3 && ./configure --prefix=/usr/local && make -j2 && make install \
    && mkdir -p /exports/open /exports/read-only /exports/denied /exports/network /exports/netmask \
    && printf 'module-target-nfs-public\n' > /exports/open/proof.txt \
    && printf 'module-target-nfs-read-only\n' > /exports/read-only/proof.txt \
    && printf 'module-target-nfs-denied\n' > /exports/denied/proof.txt \
    && printf 'module-target-nfs-network\n' > /exports/network/proof.txt \
    && printf 'module-target-nfs-netmask\n' > /exports/netmask/proof.txt \
    && chmod -R a+rX /exports
COPY entrypoint.sh /opt/module-target-entrypoint.sh
COPY exports empty.exports /etc/module-target/
ENTRYPOINT ["/bin/sh", "/opt/module-target-entrypoint.sh"]
CMD ["/usr/local/sbin/unfsd", "-d", "-e", "/run/module-target.exports"]
