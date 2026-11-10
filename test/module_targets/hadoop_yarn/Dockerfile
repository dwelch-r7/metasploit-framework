FROM apache/hadoop:3.4.2@sha256:0f79c18d27a2b15984868a41e245b09c98daa5638b573b4dbd848be650f05635
USER root
# The automatic Bourne stager probes available decoders with GNU which.
ADD --checksum=sha256:6cf383438b274ac87850adde30180b8ff9ef77ad256180eed69f165779d95742 https://vault.centos.org/7.9.2009/os/x86_64/Packages/which-2.20-7.el7.x86_64.rpm /tmp/module-target-which.rpm
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 \
    && rpm --checksig -v /tmp/module-target-which.rpm \
    && rpm -i /tmp/module-target-which.rpm \
    && rm /tmp/module-target-which.rpm
USER hadoop
