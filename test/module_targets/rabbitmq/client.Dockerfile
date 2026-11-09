FROM python:3.12.12-slim-bookworm@sha256:2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301
RUN printf '%s\n' 'pika==1.3.2 --hash=sha256:0779a7c1fafd805672796085560d290213a465e4f6f76a6fb19e378d8041a14f' > /tmp/requirements.txt \
    && pip install --no-cache-dir --only-binary=:all: --require-hashes -r /tmp/requirements.txt
COPY client.py /opt/module-target-client.py
COPY distribution.py /opt/module-target-distribution.py
CMD ["sleep", "infinity"]
