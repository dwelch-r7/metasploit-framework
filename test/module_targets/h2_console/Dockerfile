FROM ruby:3.3.13-alpine3.24@sha256:d33a40da6163631d03b560c797e44fa242b8727eb4a4062d8a645f2cdd69e659 AS vendor
COPY fetch_vendor.rb vendor.json /source/
RUN ruby /source/fetch_vendor.rb /vendor

FROM eclipse-temurin:8-jdk-jammy@sha256:c6bac7c75823864b6317e0ed70e5ac1ec15e65180b4c4ccf09ca2ebf8a8f5f99
RUN apt-get update && apt-get install -y --no-install-recommends python3 curl && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/module-target
COPY --from=vendor /vendor/ ./vendor/
COPY Bootstrap.java NativeControl.java entrypoint.sh process_state.py ./
RUN javac -cp vendor/h2-2.1.214.jar Bootstrap.java NativeControl.java && mkdir state && useradd --uid 1000 --no-create-home target && chown -R target:target /opt/module-target
USER target
ENTRYPOINT ["/bin/sh", "/opt/module-target/entrypoint.sh"]
