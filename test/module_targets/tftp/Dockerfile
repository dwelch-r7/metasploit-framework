FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    tftpd-hpa=5.2+20150808-1.2build2 tftp-hpa=5.2+20150808-1.2build2 \
    && rm -rf /var/lib/apt/lists/*
COPY files/ /srv/tftp/
RUN touch /srv/tftp/empty.txt \
    && dd if=/dev/zero of=/srv/tftp/large.bin bs=1536 count=1 status=none \
    && chown -R root:root /srv/tftp \
    && find /srv/tftp -type d -exec chmod 755 {} + \
    && find /srv/tftp -type f -exec chmod 644 {} + \
    && chmod 600 /srv/tftp/denied.txt
CMD ["/usr/sbin/in.tftpd", "--listen", "--foreground", "--address", "0.0.0.0:69", "--secure", "--user", "tftp", "/srv/tftp"]
