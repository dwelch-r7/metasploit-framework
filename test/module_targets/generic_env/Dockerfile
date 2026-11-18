FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends coreutils=8.32-4.1ubuntu1.4 python3=3.10.6-1~22.04.1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1001 --create-home --shell /bin/bash labuser \
    && mkdir -p /opt/health /opt/native-artifacts /opt/module-target-artifacts \
    && printf 'Native environment target\n' > /opt/health/index.html
COPY env_values.py native_probe.py state.py artifacts.py /opt/
CMD ["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/opt/health"]
