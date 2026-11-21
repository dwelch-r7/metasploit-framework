FROM python@sha256:ea8897698c0955ba96144bd2b7310ef7884ccce4db7a1f97ffc21fb8b89d1673
ARG SALT_VERSION=3000.1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONUNBUFFERED=1
WORKDIR /opt/module-target
# Salt's SSH client needs the real OpenSSH binaries even with an empty roster.
# Keep package selection reproducible without changing the shared Salt base.
RUN printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20240101T000000Z/ bullseye main' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20240101T000000Z/ bullseye-security main' > /etc/apt/sources.list \
 && apt-get update && apt-get install -y --no-install-recommends openssh-client \
 && dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /opt/module-target/system-packages.tsv \
 && rm -rf /var/lib/apt/lists/*
COPY requirements-runtime.txt /opt/module-target/requirements-runtime.txt
RUN python -m pip install --no-cache-dir --no-deps --require-hashes -r requirements-runtime.txt
COPY --from=api requirements-api.txt /opt/module-target/requirements-api.txt
RUN python -m pip install --no-cache-dir --no-deps --require-hashes -r requirements-api.txt
COPY --from=api sources /opt/module-target/api-sources
RUN python -m pip install --no-cache-dir --no-deps --no-build-isolation --require-hashes -r api-sources/${SALT_VERSION}.txt
COPY master minion /etc/salt/
COPY --from=api start.py health.py observe.py dependencies.py /opt/module-target/
RUN python /opt/module-target/dependencies.py
CMD ["python", "/opt/module-target/start.py"]
