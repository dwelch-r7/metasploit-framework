FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d \
    && sed -i 's,archive.ubuntu.com,security.ubuntu.com,g' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    'asterisk=1:18.10.0~dfsg+~cs6.10.40431411-2' sipsak sip-tester python3 tcpdump iproute2 netbase ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/asterisk
COPY modules.conf sip.conf extensions.conf manager.conf /etc/asterisk/
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -subj /CN=sip.module-target.test -addext subjectAltName=DNS:sip.module-target.test \
    -keyout /tmp/module-target.key -out /tmp/module-target.crt \
    && cat /tmp/module-target.crt /tmp/module-target.key > /etc/asterisk/module-target.pem \
    && chown asterisk:asterisk /etc/asterisk/module-target.pem \
    && chmod 600 /etc/asterisk/module-target.pem \
    && rm /tmp/module-target.key /tmp/module-target.crt
COPY entrypoint.sh /opt/module-target-entrypoint.sh
COPY client_api.py /opt/module-target-client-api.py
ENTRYPOINT ["/bin/sh", "/opt/module-target-entrypoint.sh"]
CMD ["asterisk", "-f", "-g", "-vvv", "-U", "asterisk"]
