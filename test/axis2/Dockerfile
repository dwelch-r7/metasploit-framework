ARG BASE_IMAGE=tomcat:9.0
FROM ${BASE_IMAGE}

# Default to the original acceptance target; labs can pin other releases.
RUN apt-get update -qq && apt-get install -y --no-install-recommends wget unzip && rm -rf /var/lib/apt/lists/*
ARG AXIS2_WAR_URL=https://archive.apache.org/dist/axis/axis2/java/core/1.6.2/axis2-1.6.2-war.zip
ARG AXIS2_WAR_SHA256=65a156e93077d3cf59d1168ee95fca263a0fa1ca50d90ee544c868591c1a75ef
RUN wget -q "$AXIS2_WAR_URL" \
    -O /tmp/axis2.zip && \
    printf '%s  /tmp/axis2.zip\n' "$AXIS2_WAR_SHA256" | sha256sum --check && \
    unzip -q /tmp/axis2.zip -d /tmp/axis2 && \
    cp /tmp/axis2/axis2.war /usr/local/tomcat/webapps/ && \
    rm -rf /tmp/axis2 /tmp/axis2.zip

# Move the bundled Tomcat apps into place (they live in webapps.dist in modern images)
RUN cp -r /usr/local/tomcat/webapps.dist/. /usr/local/tomcat/webapps/

# Restore the Server header so fingerprint checks pass (Tomcat 9 suppresses it by default)
RUN sed -i 's|<Connector port="8080"|<Connector port="8080" server="Apache-Coyote/1.1"|' \
    /usr/local/tomcat/conf/server.xml
