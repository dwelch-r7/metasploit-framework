FROM internetsystemsconsortium/bind9:9.20@sha256:66092edb53c081fa11b1fa8219e99065b0f497cb38f568ba789702a4c10e2590

COPY *.conf /etc/bind/
COPY module-target.test.zone /var/cache/bind/module-target.test.zone
COPY 192.0.2.rev /var/cache/bind/192.0.2.rev
RUN chown -R bind:bind /var/cache/bind

CMD ["-g", "-n", "2", "-c", "/etc/bind/open.conf"]
