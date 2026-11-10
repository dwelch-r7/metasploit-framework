FROM eclipse-temurin:17-jdk-jammy@sha256:f1309980e092cb762e6cbf78cf91b7fa0e7d3f3c5fc47a60a582f880b799aa48
ARG ACTIVEMQ_VERSION
ARG ACTIVEMQ_SHA512
ADD https://archive.apache.org/dist/activemq/${ACTIVEMQ_VERSION}/apache-activemq-${ACTIVEMQ_VERSION}-bin.tar.gz /tmp/activemq.tar.gz
RUN printf '%s  /tmp/activemq.tar.gz\n' "$ACTIVEMQ_SHA512" | sha512sum --check - \
 && mkdir /opt/activemq \
 && tar -xzf /tmp/activemq.tar.gz --strip-components=1 -C /opt/activemq \
 && rm /tmp/activemq.tar.gz \
 && apt-get update \
 && apt-get install --yes --no-install-recommends curl procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --uid 1500 --user-group --no-create-home --home-dir /opt/activemq --shell /bin/sh activemq \
 && sed -i 's/value="127.0.0.1"/value="0.0.0.0"/' /opt/activemq/conf/jetty.xml \
 && chown -R activemq:activemq /opt/activemq
COPY NativeControl.java /opt/module-target/NativeControl.java
RUN javac -cp '/opt/activemq/lib/*:/opt/activemq/lib/optional/*' /opt/module-target/NativeControl.java
ENV ACTIVEMQ_OPTS_MEMORY="-Xms64m -Xmx384m" JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=2"
WORKDIR /opt/activemq
USER activemq
CMD ["bin/activemq", "console"]
