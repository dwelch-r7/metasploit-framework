FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

ARG SNMP_PACKAGE_VERSION=5.9.1+dfsg-1ubuntu2.10
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends snmpd="${SNMP_PACKAGE_VERSION}" snmp="${SNMP_PACKAGE_VERSION}" python3 \
    && rm -rf /var/lib/apt/lists/*

COPY snmpd.conf /etc/snmp/module-target.conf
COPY native_probe.py /opt/native_probe.py
ENV MIBS=""
CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/module-target.conf"]
