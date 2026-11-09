ARG BASE_IMAGE=ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
FROM ${BASE_IMAGE}

ARG RSYNC_PACKAGE_VERSION=3.2.7-0ubuntu0.22.04.7
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rsync="${RSYNC_PACKAGE_VERSION}" python3 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /srv/share \
    && printf 'rsync-module-target-proof\n' > /srv/share/proof.txt \
    && printf 'labuser:labpassword\n' > /etc/rsyncd.secrets \
    && chmod 600 /etc/rsyncd.secrets

COPY rsyncd.conf empty.conf motd.txt native_probe.py /opt/
CMD ["rsync", "--daemon", "--no-detach", "--config", "/opt/rsyncd.conf"]
