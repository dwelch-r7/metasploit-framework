FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11 AS build
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    cmake gcc make libc6-dev python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:b05e47734e2e39c0b00511ed6dc22e71f1b5bf7864b86280653a5128d171c0ed https://codeload.github.com/open62541/open62541/tar.gz/refs/tags/v1.5.10 /source/open62541.tar.gz
RUN tar -xzf /source/open62541.tar.gz -C /source
COPY CMakeLists.txt lab-server.c lab-client.c /lab-source/
RUN cmake -S /lab-source -B /build -DCMAKE_BUILD_TYPE=Release \
      -DOPEN62541_SOURCE=/source/open62541-1.5.10 -DBUILD_SHARED_LIBS=OFF \
      -DUA_BUILD_EXAMPLES=OFF -DUA_BUILD_UNIT_TESTS=OFF -DUA_ENABLE_ENCRYPTION=OFF \
      -DUA_ENABLE_PUBSUB=OFF -DUA_MULTITHREADING=0 \
    && cmake --build /build --parallel 2 \
    && mkdir /lab-output \
    && cp /build/opcua-lab-server /build/opcua-lab-client /lab-output/ \
    && cd /lab-output && sha256sum opcua-lab-server opcua-lab-client > binaries.sha256 \
    && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' > build-packages.tsv

FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 \
    && dpkg-query -W -f '${binary:Package}\t${Version}\t${Architecture}\n' > /opt/runtime-packages.tsv \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /lab-output/ /opt/opcua-bin/
COPY --from=build /source/open62541-1.5.10/LICENSE /opt/opcua-bin/UPSTREAM-LICENSE
COPY supervise.py health.py /opt/opcua-lab/
CMD ["python3", "/opt/opcua-lab/supervise.py"]
