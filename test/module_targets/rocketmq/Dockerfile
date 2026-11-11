ARG ROCKETMQ_IMAGE=apache/rocketmq@sha256:79b41e2956de07c576949bedf8f9bc5eac9f1eeb72362b89ee2344219e5a46b1
FROM ${ROCKETMQ_IMAGE} AS vendor

FROM eclipse-temurin@sha256:057a0daec60e87c96571bf5c9c7792065bcb19e804d584cd37d4144038a35717 AS compiler
ARG ROCKETMQ_VERSION=4.9.4
COPY --from=vendor /home/rocketmq/rocketmq-${ROCKETMQ_VERSION}/lib /sdk/lib
COPY NativeProbe.java /sdk/NativeProbe.java
RUN javac --release 8 -proc:none -cp '/sdk/lib/*' -d /sdk/classes /sdk/NativeProbe.java

FROM vendor
COPY --from=compiler /sdk/classes /lab/classes
COPY start.sh native.sh health.sh /lab/
CMD ["bash", "/lab/start.sh"]
