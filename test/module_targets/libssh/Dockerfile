FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11 AS build
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cmake gcc g++ make libc6-dev python3 ca-certificates patch libgcrypt20-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:54e86dd5dc20e5367e58f3caab337ce37675f863f80df85b6b1614966a337095 https://www.libssh.org/files/0.7/libssh-0.7.5.tar.xz /archives/libssh-0.7.5.tar.xz
ADD --checksum=sha256:1d607d3859274f755942324afb0f887ee22edd157f9596a2e69e3a28ec6d1092 https://www.libssh.org/files/0.7/libssh-0.7.6.tar.xz /archives/libssh-0.7.6.tar.xz
ADD --checksum=sha256:302f31f606f2368cd3ce77d7a69f7464c18eae176e73e59102e0524401bd29d0 https://www.libssh.org/files/0.8/libssh-0.8.3.tar.xz /archives/libssh-0.8.3.tar.xz
ADD --checksum=sha256:6bb07713021a8586ba2120b2c36c468dc9ac8096d043f9b1726639aa4275b81b https://www.libssh.org/files/0.8/libssh-0.8.4.tar.xz /archives/libssh-0.8.4.tar.xz
COPY external/source/libssh/ssh_server_fork.patch /lab-source/ssh_server_fork.patch
COPY test/module_targets/libssh/build.py test/module_targets/libssh/version.c test/module_targets/libssh/releases.json /lab-source/
RUN python3 /lab-source/build.py && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' >/lab-output/build-packages.tsv

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-paramiko openssh-client libgcrypt20 zlib1g procps iproute2 && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' >/opt/runtime-packages.tsv && rm -rf /var/lib/apt/lists/* && useradd -u 10001 -U -d /tmp/libssh-home labssh
COPY --from=build /lab-output/ /opt/libssh/
COPY test/module_targets/libssh/supervise.py test/module_targets/libssh/health.py test/module_targets/libssh/state.py test/module_targets/libssh/native_probe.py test/module_targets/libssh/rsa-short-signature.json /opt/libssh-lab/
ENV HOME=/tmp/libssh-home
USER 10001:10001
CMD ["python3", "/opt/libssh-lab/supervise.py"]
