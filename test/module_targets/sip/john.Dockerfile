FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
RUN sed -i 's,archive.ubuntu.com,security.ubuntu.com,g' /etc/apt/sources.list \
    && apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 -o APT::Update::Error-Mode=any update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential libssl-dev zlib1g-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY john-37bebbe.tar.gz /tmp/john.tar.gz
RUN echo '9e595c25610de6dd3fa37124c57a1be76548399bb299f285d6797e60d3efb969  /tmp/john.tar.gz' | sha256sum -c - \
    && mkdir /opt/john && tar -xzf /tmp/john.tar.gz -C /opt/john --strip-components=1 && rm /tmp/john.tar.gz \
    && cd /opt/john/src && ./configure --disable-openmp --disable-native-tests \
    && make -j2 -s
ENTRYPOINT ["/opt/john/run/john"]
