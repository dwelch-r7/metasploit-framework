FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3=3.10.6-1~22.04.1 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/health /opt/module-target-tools \
    && printf 'Native Linux module target\n' > /opt/health/index.html \
    && printf '#!/bin/sh\nprintf "module-target-command-proof\\n"\n' > /opt/module-target-tools/lab-command \
    && chmod 755 /opt/module-target-tools/lab-command

COPY native_probe.py launch_session.py /opt/
CMD ["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/opt/health"]
