# The genuine original engine remains unchanged; only native client prerequisites
# are added from an immutable, normally signature-verified Debian snapshot.
FROM drachtio/drachtio-freeswitch-mrf@sha256:f68cd8de49d718af2b23ce16587fd491dd93abd8ff7129d959016101dee03f09
USER root
COPY binaries.sha256 /opt/module-target-original-binaries.sha256
RUN rm -f /etc/apt/sources.list.d/* \
 && printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20260101T000000Z/ bookworm main' > /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl=7.88.1-10+deb12u14 wget=1.21.3-1+deb12u1 inetutils-telnet=2:2.4-2+deb12u1 perl=5.36.0-7+deb12u3 \
 && sha256sum -c /opt/module-target-original-binaries.sha256 \
 && perl -MIO::Socket::INET -MJSON::PP -e 'print qq(JSON::PP ready\n)' \
 && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' > /opt/module-target-tool-packages.unsorted \
 && sort /opt/module-target-tool-packages.unsorted > /opt/module-target-tool-packages.tsv \
 && rm /opt/module-target-tool-packages.unsorted \
 && sha256sum /usr/bin/curl /usr/bin/wget /usr/bin/telnet > /opt/module-target-tool-binaries.sha256 \
 && rm -rf /var/lib/apt/lists/*
