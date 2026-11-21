FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl xz-utils python3 libegl1 libopengl0 libglx0 libglib2.0-0 libfontconfig1 libxkbcommon0 libxkbcommon-x11-0 libxcb-cursor0 libnss3 libxcomposite1 libxdamage1 libxrandr2 libasound2 libxi6 libcups2 \
    && rm -rf /var/lib/apt/lists/*
ARG CALIBRE_VERSION=7.14.0
ARG CALIBRE_SHA512
ADD https://download.calibre-ebook.com/${CALIBRE_VERSION}/calibre-${CALIBRE_VERSION}-x86_64.txz /tmp/calibre.txz
RUN test -n "$CALIBRE_SHA512" \
    && printf '%s  %s\n' "$CALIBRE_SHA512" /tmp/calibre.txz | sha512sum -c - \
    && mkdir /opt/calibre \
    && tar -xJf /tmp/calibre.txz -C /opt/calibre \
    && rm /tmp/calibre.txz \
    && useradd --create-home --uid 1000 app
COPY native.py /opt/module-target-native.py
COPY start.sh /opt/module-target-start.sh
ENV PATH=/opt/calibre:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin QT_QPA_PLATFORM=offscreen PYTHONHASHSEED=0 LANG=C.UTF-8 LC_ALL=C.UTF-8
USER app
WORKDIR /home/app
CMD ["sh", "/opt/module-target-start.sh"]
