FROM python:3.8.20-slim-bookworm@sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f

ARG WERKZEUG_VERSION=3.0.3
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 USER=lab LOGNAME=lab HOME=/home/lab
COPY packages.json install.py /opt/module-target-werkzeug/
RUN python /opt/module-target-werkzeug/install.py "$WERKZEUG_VERSION" && \
    useradd --create-home --uid 1001 --shell /bin/sh lab && \
    printf '0123456789abcdef0123456789abcdef\n' > /etc/machine-id && \
    chmod 0444 /etc/machine-id && \
    printf 'module-target-werkzeug-foreign\n' > /opt/module-target-werkzeug/foreign.txt && \
    chmod 0444 /opt/module-target-werkzeug/foreign.txt
COPY app.py native_probe.py /opt/module-target-werkzeug/
USER 1001:1001
WORKDIR /opt/module-target-werkzeug
CMD ["python", "-B", "/opt/module-target-werkzeug/app.py"]
