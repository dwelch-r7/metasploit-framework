FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99

ARG JBOSS_URL=https://downloads.sourceforge.net/project/jboss/JBoss/JBoss-4.2.3.GA/jboss-4.2.3.GA-jdk6.zip
ARG JBOSS_SHA256=48797e150ee7dd6e035290fab86f17a5fe7d174b4980e941b833369b80273620
RUN curl --fail --location --retry 3 "$JBOSS_URL" -o /tmp/jboss.zip \
    && echo "$JBOSS_SHA256  /tmp/jboss.zip" | sha256sum -c - \
    && cd /opt && jar xf /tmp/jboss.zip \
    && mv jboss-4.2.3.GA jboss && rm /tmp/jboss.zip \
    && chmod 755 /opt/jboss/bin/*.sh
COPY start.sh fixture /opt/module-target/
RUN chmod 755 /opt/module-target/start.sh \
    && cd /opt/module-target && jar cf fixture.war index.jsp hold.jsp
ENV JAVA_OPTS="-Xms64m -Xmx384m -Djava.net.preferIPv4Stack=true"
WORKDIR /opt/jboss
ENTRYPOINT ["/opt/module-target/start.sh"]
