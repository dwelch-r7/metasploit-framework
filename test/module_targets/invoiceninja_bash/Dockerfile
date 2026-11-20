FROM invoiceninja/invoiceninja@sha256:1999d70953484cc49a3c9386ac8d8a6e8b2730c0302b9901ac14a074f7038fc9
USER 0
# The official app image lacks the interpreter required by reverse_bash.
# https://pkgs.alpinelinux.org/package/v3.20/main/x86_64/bash
RUN apk add --no-cache bash=5.2.26-r0 \
    && apk info -vv > /opt/module-target-session-packages.txt
USER 1500
