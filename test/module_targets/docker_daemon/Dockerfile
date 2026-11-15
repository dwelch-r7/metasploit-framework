ARG DOCKER_ENGINE_IMAGE=docker:26.1.4-dind@sha256:b32df6450ef70d803237fd21eb4ddf8b3dda13378075c39306c7c19f0ced079e
FROM registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373 AS registry
FROM ${DOCKER_ENGINE_IMAGE} AS engine
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS seed
FROM debian:bookworm-slim@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates cron curl iproute2 iptables python3 python-is-python3 tini procps nginx-light openssl apache2-utils && rm -rf /var/lib/apt/lists/*
COPY --from=engine /usr/local/bin/ /usr/local/bin/
COPY --from=registry /bin/registry /usr/local/bin/registry
COPY --from=seed / /opt/module-target-seed/
RUN tar -C /opt/module-target-seed -cf /opt/module-target-seed.tar . && rm -rf /opt/module-target-seed && dpkg-query -W > /opt/module-target-packages.txt
COPY nginx.conf /etc/nginx/nginx.conf
COPY registry.yml /etc/docker/registry/native.yml
RUN htpasswd -bc /etc/nginx/module-target.htpasswd module-target-user module-target-password && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=target -addext subjectAltName=DNS:target,DNS:localhost,IP:127.0.0.1 -keyout /etc/nginx/module-target.key -out /etc/nginx/module-target.crt
COPY entrypoint.py /opt/module-target-entrypoint.py
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/bin/python3", "/opt/module-target-entrypoint.py"]
