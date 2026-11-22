FROM php:7.4.33-apache-bullseye@sha256:18b3497ee7f2099a90b66c23a0bc3d5261b12bab367263e1b40e9b004c39e882
RUN printf '%s\n' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20230301T000000Z/ bullseye main' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20230301T000000Z/ bullseye-security main' > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends libncurses5 \
 && rm -rf /var/lib/apt/lists/*

ARG LINUXKI_VERSION=6.0-1
ARG LINUXKI_REVISION=5b04f4b36fd85593cea628f04886a2f1dc6df68e
ARG LINUXKI_SHA256=953a9b597a8da51df89ac9e5dbe2e085e14d4bc39525811a87e8f22797a0ab08
RUN curl --fail --location --silent --show-error \
    "https://raw.githubusercontent.com/HewlettPackard/LinuxKI/${LINUXKI_REVISION}/rpms/linuxki_${LINUXKI_VERSION}_all.deb" -o /tmp/linuxki.deb \
 && echo "${LINUXKI_SHA256}  /tmp/linuxki.deb" | sha256sum -c - \
 && dpkg --install /tmp/linuxki.deb \
 && ln -s /opt/linuxki /var/www/html/linuxki \
 && printf '%s\n' '<Directory /opt/linuxki>' 'Require all granted' '</Directory>' > /etc/apache2/conf-enabled/module-target-linuxki.conf \
 && printf '%s\n' 'display_errors=Off' 'log_errors=On' 'error_log=/dev/stderr' > /usr/local/etc/php/conf.d/module-target-errors.ini \
 && php --version \
 && ldd /opt/linuxki/kiinfo \
 && rm /tmp/linuxki.deb
