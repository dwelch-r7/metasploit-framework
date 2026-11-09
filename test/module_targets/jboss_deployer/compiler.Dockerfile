FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99

ARG ANT_URL=https://archive.apache.org/dist/ant/binaries/apache-ant-1.10.15-bin.tar.gz
ARG ANT_SHA512=d78427aff207592c024ff1552dc04f7b57065a195c42d398fcffe7a0145e8d00cd46786f5aa52e77ab0fdf81334f065eb8011eecd2b48f7228e97ff4cb20d16c
RUN curl --fail --location --retry 3 "$ANT_URL" -o /tmp/ant.tar.gz \
    && echo "$ANT_SHA512  /tmp/ant.tar.gz" | sha512sum -c - \
    && mkdir -p /opt/ant /compiler \
    && tar xzf /tmp/ant.tar.gz --strip-components=1 -C /opt/ant \
    && rm /tmp/ant.tar.gz
CMD ["sh", "-c", "cp /opt/ant/lib/ant.jar /opt/ant/lib/ant-launcher.jar /opt/ant/LICENSE /opt/ant/NOTICE /compiler/ && touch /compiler/ready && exec sleep infinity"]
