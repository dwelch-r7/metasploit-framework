FROM vulhub/opentsdb:2.4.0@sha256:cfbee84dc40bbe03cb1556634ecf922fa10fd241d46a13029cbd81573a97862d
ARG RELEASE_URL=https://github.com/OpenTSDB/opentsdb/releases/download/v2.4.1/opentsdb-2.4.1_all.deb
ARG RELEASE_SHA256=39c15a1fe6130c642659dc0f88591349e7306791125d5e6623fc7ee5de040947
ADD ${RELEASE_URL} /tmp/opentsdb-release.deb
RUN printf '%s  /tmp/opentsdb-release.deb\n' "${RELEASE_SHA256}" | sha256sum --check - \
 && dpkg -i /tmp/opentsdb-release.deb \
 && rm /tmp/opentsdb-release.deb
