FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d \
    && sed -i 's,archive.ubuntu.com,security.ubuntu.com,g' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends samba smbclient python3 openssl tcpdump iproute2 netbase \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd directory_admins \
    && for account in directory_reader rpc_admin policy_user unicode_user local_alice local_bob; do useradd -m "$account"; done \
    && usermod -aG directory_admins rpc_admin \
    && mkdir -p /run/samba /var/lib/module-target/sysvol /var/lib/module-target/empty /var/lib/module-target/empty_policies /var/lib/module-target/protected /var/lib/module-target/session /var/log/module-target
COPY smb.conf /etc/samba/smb.conf
COPY client.conf /opt/module-target-client.conf
COPY credentials.json /opt/module-target-credentials.json
COPY entrypoint.py /opt/module-target-entrypoint.py
COPY policy/ /var/lib/module-target/sysvol/
RUN printf 'Module target native SMB read\n' > /var/lib/module-target/session/health.txt \
    && printf 'Module target native policy account proof\n' > /var/lib/module-target/session/account-proof.txt \
    && mkdir -p /var/lib/module-target/empty_policies/dirlab.test/Policies \
    && cp -a /var/lib/module-target/sysvol/. /var/lib/module-target/protected/ \
    && chmod -R a+rX /var/lib/module-target \
    && chmod -R 700 /var/lib/module-target/protected
ENTRYPOINT ["python3", "/opt/module-target-entrypoint.py"]
