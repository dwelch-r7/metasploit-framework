FROM ubuntu:22.04@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11

RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    dovecot-core=1:2.3.16+dfsg1-3ubuntu2.9 \
    dovecot-pop3d=1:2.3.16+dfsg1-3ubuntu2.9 \
    dovecot-imapd=1:2.3.16+dfsg1-3ubuntu2.9 \
    openssl=3.0.2-0ubuntu1.30 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 labmail \
    && useradd --uid 1000 --gid 1000 --home-dir /srv/mail labmail \
    && mkdir -p /srv/mail/Maildir/cur /srv/mail/Maildir/new /srv/mail/Maildir/tmp /etc/dovecot/certificates \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=localhost \
       -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' \
       -keyout /etc/dovecot/certificates/server.key -out /etc/dovecot/certificates/server.crt \
    && chmod 600 /etc/dovecot/certificates/server.key

COPY dovecot.conf required.conf users /etc/dovecot/
COPY message.eml /srv/mail/Maildir/new/module-target-message
RUN chown -R labmail:labmail /srv/mail \
    && chown root:dovecot /etc/dovecot/users && chmod 640 /etc/dovecot/users
CMD ["dovecot", "-F", "-c", "/etc/dovecot/dovecot.conf"]
