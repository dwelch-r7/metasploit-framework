FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99 AS builder
RUN apt-get update \
 && apt-get install --yes --no-install-recommends autoconf automake make git curl gnuplot-nox python-is-python3 \
 && rm -rf /var/lib/apt/lists/*
ARG SOURCE_REVISION=0f681b7545d9999506900da5f1c4dbe433dbfb43
ENV JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=2"
RUN git init /src \
 && git -C /src remote add origin https://github.com/OpenTSDB/opentsdb.git \
 && git -C /src fetch --depth 1 origin "${SOURCE_REVISION}" \
 && git -C /src checkout --detach FETCH_HEAD \
 && test "$(git -C /src rev-parse HEAD)" = "${SOURCE_REVISION}"
WORKDIR /src
# The concrete jar target avoids running the upstream unit suite during a lab
# image build. Build the genuine GWT assets and install the full runtime files.
RUN ./bootstrap \
 && ./configure --prefix=/usr --sysconfdir=/etc \
 && make -j2 tsdb-2.5.0-RC1.jar .staticroot-stamp
RUN make install-exec-am DESTDIR=/stage \
 && make install-data-lib install-data-tools install-data-bin install-data-etc DESTDIR=/stage \
 && mkdir -p /stage/usr/share/opentsdb/static \
 && cp -Lr staticroot/. /stage/usr/share/opentsdb/static/ \
 && mkdir -p /stage/usr/local/share/module-target-provenance \
 && git rev-parse HEAD > /stage/usr/local/share/module-target-provenance/opentsdb-revision.txt \
 && find /stage/usr/share/opentsdb -type f -name '*.jar' -exec sha256sum {} + > /stage/usr/local/share/module-target-provenance/opentsdb-jars.sha256 \
 && dpkg-query -W > /stage/usr/local/share/module-target-provenance/builder-packages.txt

FROM vulhub/opentsdb:2.4.0@sha256:cfbee84dc40bbe03cb1556634ecf922fa10fd241d46a13029cbd81573a97862d
# Keep the genuine HBase/JRE/Gnuplot and ordinary vendor entrypoint, replacing
# all OpenTSDB runtime dependencies and UI with the complete official fixed tree.
RUN rm -rf /usr/share/opentsdb/lib /usr/share/opentsdb/static /usr/share/opentsdb/bin /usr/share/opentsdb/tools
COPY --from=builder /stage/ /
