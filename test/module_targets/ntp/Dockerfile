FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ntp=1:4.2.8p15+dfsg-1ubuntu2 \
    && rm -rf /var/lib/apt/lists/*
COPY open.conf closed.conf /etc/module-target/
CMD ["/usr/sbin/ntpd", "-n", "-c", "/etc/module-target/open.conf", "-p", "/tmp/module-target-ntpd.pid", "-l", "/dev/stdout"]
