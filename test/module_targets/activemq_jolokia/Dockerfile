FROM eclipse-temurin:17-jdk-jammy@sha256:f1309980e092cb762e6cbf78cf91b7fa0e7d3f3c5fc47a60a582f880b799aa48
ARG ACTIVEMQ_VERSION
ARG ACTIVEMQ_SHA512
ARG BROKER_NAME
ARG WEB_PREFIX=""
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
 && sed -i "s/brokerName=\"localhost\"/brokerName=\"${BROKER_NAME}\"/" /opt/activemq/conf/activemq.xml \
 && if [ -n "$WEB_PREFIX" ]; then \
      sed -i -e "s|value=\"/api\"|value=\"$WEB_PREFIX/api\"|" \
             -e "s|value=\"/admin\"|value=\"$WEB_PREFIX/admin\"|" \
             -e "s|/api/\*|$WEB_PREFIX/api/*|g" /opt/activemq/conf/jetty.xml; \
    fi \
 && chown -R activemq:activemq /opt/activemq
COPY activemq_openwire/NativeControl.java activemq_jolokia/NativeJmxProof.java /opt/module-target/
RUN javac -cp '/opt/activemq/lib/*:/opt/activemq/lib/optional/*' /opt/module-target/*.java
ENV ACTIVEMQ_OPTS_MEMORY="-Xms64m -Xmx384m" JAVA_TOOL_OPTIONS="-XX:ActiveProcessorCount=2"
WORKDIR /opt/activemq
USER activemq
CMD ["bin/activemq", "console"]
