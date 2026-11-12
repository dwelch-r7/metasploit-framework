FROM python@sha256:ea8897698c0955ba96144bd2b7310ef7884ccce4db7a1f97ffc21fb8b89d1673
ARG SALT_VERSION=3000.1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONUNBUFFERED=1
WORKDIR /opt/module-target
COPY requirements-runtime.txt /opt/module-target/requirements-runtime.txt
RUN python -m pip install --no-cache-dir --no-deps --require-hashes -r requirements-runtime.txt
COPY sources /opt/module-target/sources
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation --require-hashes -r sources/${SALT_VERSION}.txt
COPY master minion /etc/salt/
COPY health.py /opt/module-target/health.py
RUN mkdir -p /etc/salt/pki /var/cache/salt /var/run/salt /var/log/salt /srv/salt /srv/pillar
CMD ["salt-master", "--log-level=warning", "--config-dir=/etc/salt"]
