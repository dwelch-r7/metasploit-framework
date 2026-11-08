FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends exim4-daemon-light python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --home-dir /nonexistent --shell /usr/sbin/nologin module_target \
    && mkdir -p /var/spool/exim4/module-target-mail \
    && chown Debian-exim:Debian-exim /var/spool/exim4/module-target-mail

COPY exim.conf /etc/exim4/module-target.conf
COPY entrypoint.sh native_probe.py /opt/
CMD ["bash", "/opt/entrypoint.sh"]
