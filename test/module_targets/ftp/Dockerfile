FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends proftpd-core python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --home-dir /srv/ftp --shell /bin/sh module_target \
    && echo 'module_target:module-target-password' | chpasswd \
    && mkdir -p /srv/ftp /run/proftpd \
    && rm -f /srv/ftp/welcome.msg \
    && chmod 0777 /srv/ftp \
    && printf 'module-target-ftp-marker\n' > /srv/ftp/module-target.txt

COPY proftpd.conf /etc/proftpd/module-target.conf
COPY entrypoint.sh native_probe.py /opt/
CMD ["bash", "/opt/entrypoint.sh"]
