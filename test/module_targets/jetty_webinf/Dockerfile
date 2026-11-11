ARG JETTY_IMAGE
FROM ${JETTY_IMAGE}

RUN mkdir -p webapps/ROOT/WEB-INF/classes
COPY --chown=jetty:jetty web.xml /var/lib/jetty/webapps/ROOT/WEB-INF/web.xml
COPY --chown=jetty:jetty unicode.txt /var/lib/jetty/webapps/ROOT/WEB-INF/unicode.txt
COPY --chown=jetty:jetty module-target.ini /var/lib/jetty/start.d/module-target.ini
RUN printf 'module-target-jetty-index\n' > webapps/ROOT/index.html \
    && printf 'module-target-jetty-private\n' > webapps/ROOT/WEB-INF/short.txt \
    && : > webapps/ROOT/WEB-INF/empty.txt \
    && printf '\000\377\r\nmodule-target-jetty\000' > webapps/ROOT/WEB-INF/binary.dat \
    && printf '# Synthetic application configuration\nmessage=module-target-jetty\n' > webapps/ROOT/WEB-INF/classes/settings.properties \
    && { i=0; while [ "$i" -lt 1024 ]; do printf 'module-target-jetty-record-%04d-abcdefghijklmnopqrstuvwxyz\n' "$i"; i=$((i + 1)); done; } > webapps/ROOT/WEB-INF/large.txt
RUN rm -f /var/lib/jetty/jetty.start

ENV JAVA_OPTIONS="-Xms32m -Xmx64m -Xss256k -XX:MaxMetaspaceSize=96m -XX:ReservedCodeCacheSize=32m -XX:MaxDirectMemorySize=16m -XX:ActiveProcessorCount=1"
