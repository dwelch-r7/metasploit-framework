FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    irssi=1.2.3-1ubuntu4 ngircd=26.1-1 python3=3.10.6-1~22.04.1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1001 --create-home --shell /bin/bash labuser \
    && useradd --uid 1002 --create-home --shell /bin/bash otheruser \
    && mkdir -p /run/module-target-ngircd /opt/native-artifacts /opt/module-target-artifacts \
    && chown 65534:65534 /run/module-target-ngircd
COPY ngircd.conf /etc/ngircd/module-target.conf
CMD ["/usr/sbin/ngircd", "--nodaemon", "--config", "/etc/ngircd/module-target.conf"]
