FROM ruby:3.3.13-alpine3.24@sha256:d33a40da6163631d03b560c797e44fa242b8727eb4a4062d8a645f2cdd69e659 AS certificates
COPY certificates.rb /opt/certificates.rb
RUN ruby /opt/certificates.rb

FROM eclipse-mosquitto:2.0.22@sha256:81a6193ae693942a3231cd3ac52875b02b7e3a19da671b2fb4b55cc874c5b279
COPY *.conf /mosquitto/config/
COPY --from=certificates /certificates /mosquitto/config/certificates
RUN mosquitto_passwd -b -c /mosquitto/config/passwords lab-mqtt-user lab-mqtt-password \
    && chown -R mosquitto:mosquitto /mosquitto/config \
    && chmod 600 /mosquitto/config/passwords /mosquitto/config/certificates/server.key
CMD ["mosquitto", "-c", "/mosquitto/config/open.conf"]
