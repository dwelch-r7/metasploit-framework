ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG AJP_ATTRIBUTES

COPY server.xml /tmp/module-target-server.xml
RUN sed "s/@AJP_ATTRIBUTES@/${AJP_ATTRIBUTES}/" /tmp/module-target-server.xml > conf/server.xml \
    && mkdir -p webapps/ROOT/WEB-INF \
    && printf 'module-target-ghostcat-private\n' > webapps/ROOT/WEB-INF/short.txt \
    && : > webapps/ROOT/WEB-INF/empty.txt \
    && printf '\000\377\r\nmodule-target\000' > webapps/ROOT/WEB-INF/binary.txt \
    && awk 'BEGIN { for (i = 1; i <= 1024; i++) printf "module-target-record-%04d-abcdefghijklmnopqrstuvwxyz\n", i }' > webapps/ROOT/WEB-INF/large.txt \
    && printf '<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1"><display-name>Module target Ghostcat</display-name></web-app>\n' > webapps/ROOT/WEB-INF/web.xml \
    && printf 'module-target-ghostcat-http\n' > webapps/ROOT/index.txt
COPY unicode.txt webapps/ROOT/WEB-INF/unicode.txt
CMD ["catalina.sh", "run"]
