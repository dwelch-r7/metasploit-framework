FROM capture_client_base
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends freetds-bin=1.3.17+ds-2+deb13u1 python3-pycryptodome=3.20.0+dfsg-3 \
    && dpkg-query -W freetds-bin libsybdb5 python3-pycryptodome >> /opt/module-target-client-packages.txt \
    && rm -rf /var/lib/apt/lists/*
COPY client.py /opt/module-target-database-client.py
COPY ntlm.py /opt/module-target-ntlm.py
