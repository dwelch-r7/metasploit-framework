ARG BROKER_IMAGE
FROM ruby:3.3.13-alpine3.24@sha256:d33a40da6163631d03b560c797e44fa242b8727eb4a4062d8a645f2cdd69e659 AS certificates
COPY mqtt/certificates.rb /opt/certificates.rb
RUN ruby /opt/certificates.rb

FROM ${BROKER_IMAGE}
COPY --from=certificates /certificates /opt/module-target-certificates
COPY rabbitmq/rabbitmq.conf /etc/rabbitmq/rabbitmq.conf
COPY rabbitmq/definitions.json /etc/rabbitmq/definitions.json
# Newer official images otherwise override the explicit loopback guest policy.
RUN rm -f /etc/rabbitmq/conf.d/10-defaults.conf \
    && chown -R rabbitmq:rabbitmq /opt/module-target-certificates && chmod 600 /opt/module-target-certificates/server.key
