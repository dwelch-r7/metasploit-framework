FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3=3.10.6-1~22.04.1 gnupg=2.2.27-3ubuntu2.5 gpg=2.2.27-3ubuntu2.5 gpg-agent=2.2.27-3ubuntu2.5 gpgconf=2.2.27-3ubuntu2.5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1001 --home-dir '/home/lab space' --create-home --shell /bin/bash labuser \
    && mkdir -p /opt/health /opt/native-artifacts /opt/module-target-artifacts \
    && printf 'Native GnuPG target\n' > /opt/health/index.html
COPY fixture_native.py state.py /opt/
CMD ["python3", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/opt/health"]
