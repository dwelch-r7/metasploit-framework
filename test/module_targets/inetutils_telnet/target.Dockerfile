ARG BASE_IMAGE=ubuntu:noble-20260113@sha256:a4453623f2f8319cfff65c43da9be80fe83b1a7ce689579b475867d69495b782
FROM ${BASE_IMAGE}
ARG DISTRO=noble
ARG SNAPSHOT=20260210T000000Z
ARG INETUTILS_VERSION=2:2.5-3ubuntu4
ADD --checksum=sha256:641de77d8f142cfd62a1a6f964ba67b20754d3337c480efb529d086075a06c9a https://archive.ubuntu.com/ubuntu/pool/main/c/ca-certificates/ca-certificates_20240203_all.deb /opt/bootstrap-ca.deb
RUN dpkg-deb -x /opt/bootstrap-ca.deb /opt/bootstrap-ca \
 && cat /opt/bootstrap-ca/usr/share/ca-certificates/mozilla/*.crt > /opt/bootstrap-ca.pem \
 && rm -rf /opt/bootstrap-ca /opt/bootstrap-ca.deb
RUN rm -f /etc/apt/sources.list.d/* \
 && printf '%s\n' "deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/${SNAPSHOT}/ ${DISTRO} main universe" "deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/${SNAPSHOT}/ ${DISTRO}-updates main universe" "deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/${SNAPSHOT}/ ${DISTRO}-security main universe" > /etc/apt/sources.list \
 && printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod +x /usr/sbin/policy-rc.d \
 && apt-get -o Acquire::https::CaInfo=/opt/bootstrap-ca.pem update \
 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CaInfo=/opt/bootstrap-ca.pem install -y --no-install-recommends ca-certificates inetutils-telnetd=${INETUTILS_VERSION} inetutils-inetd=${INETUTILS_VERSION} inetutils-telnet=${INETUTILS_VERSION} python3 curl bash passwd login \
 && useradd --uid 1001 --create-home --shell /bin/bash labuser \
 && printf 'labuser:module-target-telnet-password\n' | chpasswd \
 && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' > /opt/module-target-packages.tsv \
 && sha256sum /usr/sbin/telnetd /usr/sbin/inetutils-inetd /usr/bin/telnet /bin/login > /opt/module-target-binaries.sha256 \
 && rm -rf /var/lib/apt/lists/*
COPY inetd.conf /opt/module-target-inetd.conf
COPY native.py snapshot.py fragment.py inspect.py /opt/module-target/
CMD ["/usr/sbin/inetutils-inetd", "--debug", "/opt/module-target-inetd.conf"]
