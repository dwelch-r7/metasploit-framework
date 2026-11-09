FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    x11vnc=0.9.16-8 xvfb=2:21.1.4-2ubuntu1.7~22.04.16 \
    python3=3.10.6-1~22.04.1 python3-pycryptodome=3.11.0+dfsg1-3ubuntu0.1 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh native_probe.py /opt/
CMD ["sh", "/opt/entrypoint.sh"]
