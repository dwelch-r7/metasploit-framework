FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11 AS build
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc make perl libc6-dev python3 ca-certificates && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:dfb8502297d9069633d0950876c6406fafadc8e531b118c58f5f8ecde06f6945 https://codeload.github.com/openssl/openssl/tar.gz/62f4033381a013c8a8edb6db5345da678495d94f /archives/1.0.1d.tar.gz
ADD --checksum=sha256:9debba36ef2db9022dbc8aca5da050b51e0d0e0b12548ef6ff39369b2ee1dca3 https://codeload.github.com/openssl/openssl/tar.gz/0d8776344cd7965fadd870e361503985df9c45bb /archives/1.0.1f.tar.gz
ADD --checksum=sha256:25db99e6d8cee3acae93ba78e203ddf737c4447e6be8ec0636a149986eed6998 https://codeload.github.com/openssl/openssl/tar.gz/b2d951e4232d2f90168f9a3dd0b7df9ecf2d81a8 /archives/1.0.1g.tar.gz
COPY build.py releases.json /lab-source/
RUN python3 /lab-source/build.py && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' > /output/opt/openssl/build-packages.tsv

COPY conditioned_server.c build_conditioned.py /lab-source/
RUN python3 /lab-source/build_conditioned.py

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 openssl procps iproute2 && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' > /opt/runtime-packages.tsv && rm -rf /var/lib/apt/lists/* && useradd -u 10001 -U -d /tmp/heartbleed-home labtls
COPY --from=build /output/opt/openssl/ /opt/openssl/
ENV OPENSSL_CONF=/opt/openssl/1.0.1g/ssl/openssl.cnf
COPY supervise.py health.py wire.py native_probe.py conditioned_probe.py starttls.py starttls_probe.py ec_probe.py calibrate.py state.py /opt/heartbleed-lab/
USER 10001:10001
CMD ["python3", "/opt/heartbleed-lab/supervise.py"]
