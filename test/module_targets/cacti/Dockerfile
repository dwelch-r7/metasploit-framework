FROM vulhub/cacti:1.2.22@sha256:5ff2bd5ee6091ea8823959cf41b29bfcf8290236d38588a05f187b66db28e025

ARG CACTI_REVISION
ARG CACTI_ARCHIVE_SHA256
ARG CACTI_INSTALL_INTL_PCNTL=false
COPY install-release.sh /tmp/install-release.sh
RUN bash /tmp/install-release.sh && rm /tmp/install-release.sh
