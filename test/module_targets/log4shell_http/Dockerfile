FROM ruby:3.3.13-alpine3.24@sha256:d33a40da6163631d03b560c797e44fa242b8727eb4a4062d8a645f2cdd69e659 AS vendor
COPY fetch_vendor.rb vendor.json /source/
RUN ruby /source/fetch_vendor.rb /vendor

FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99
WORKDIR /opt/module-target
COPY --from=vendor /vendor/ ./vendor/
COPY Target.java log4j2.xml entrypoint.sh ./
RUN javac -cp vendor/log4j-api-2.14.1.jar:vendor/log4j-core-2.14.1.jar Target.java
ENTRYPOINT ["/bin/sh", "/opt/module-target/entrypoint.sh"]
