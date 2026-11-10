FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99
RUN apt-get update \
 && apt-get install --yes --no-install-recommends curl procps libc6-i386 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1500 --user-group --no-create-home --home-dir /opt/activemq --shell /bin/sh activemq
ARG ARCHIVE_URL
ARG ARCHIVE_SHA512
ADD ${ARCHIVE_URL} /tmp/activemq.tar.gz
RUN printf '%s  /tmp/activemq.tar.gz\n' "$ARCHIVE_SHA512" | sha512sum --check - \
 && mkdir /opt/activemq \
 && tar -xzf /tmp/activemq.tar.gz --strip-components=1 -C /opt/activemq \
 && rm /tmp/activemq.tar.gz \
 && chown -R activemq:activemq /opt/activemq
COPY NativeControl.java /opt/module-target/
COPY native /opt/module-target/native
RUN javac -cp '/opt/activemq/lib/*:/opt/activemq/lib/optional/*' /opt/module-target/NativeControl.java \
 && javac -d /opt/module-target/native /opt/module-target/native/metasploit/Payload.java \
 && jar cf /opt/module-target/native-proof.jar -C /opt/module-target/native metasploit/Payload.class
ENV ACTIVEMQ_OPTS="-Xms64m -Xmx256m -XX:ActiveProcessorCount=2" ACTIVEMQ_OPTS_MEMORY="-Xms64m -Xmx256m" JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=2"
WORKDIR /opt/activemq
USER activemq
CMD ["sh", "-c", "if test -f bin/run.jar; then exec bin/activemq; else exec bin/activemq console; fi"]
