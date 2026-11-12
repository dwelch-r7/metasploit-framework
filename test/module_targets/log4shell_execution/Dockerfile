FROM ruby:3.3.13-alpine3.24@sha256:d33a40da6163631d03b560c797e44fa242b8727eb4a4062d8a645f2cdd69e659 AS vendor
COPY log4shell_http/fetch_vendor.rb /source/fetch_vendor.rb
COPY log4shell_http/vendor.json /source/vendor.json
RUN ruby /source/fetch_vendor.rb /vendor
COPY log4shell_execution/vendor.json /source/vendor.json
RUN ruby /source/fetch_vendor.rb /vendor

FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99
WORKDIR /opt/module-target
COPY --from=vendor /vendor/ ./vendor/
COPY log4shell_http/Target.java log4shell_http/log4j2.xml ./
COPY log4shell_execution/ExecutionBootstrap.java ./
COPY log4shell_execution/NativeFactory.java log4shell_execution/NativeTranslet.java log4shell_execution/NativePayload.java ./native/
COPY log4shell_execution/entrypoint.sh ./
RUN javac -cp 'vendor/*' Target.java ExecutionBootstrap.java && \
    javac -cp 'vendor/*' -d native native/*.java && \
    jar cf native/native-proof.jar -C native NativeFactory.class && \
    java -cp 'vendor/*:native' NativePayload native/NativeTranslet.class native/beanutils.bin
ENTRYPOINT ["/bin/sh", "/opt/module-target/entrypoint.sh"]
