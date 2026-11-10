FROM apache/druid:26.0.0@sha256:9a3a07819058693b29bb5fc145e071c3b3a1f551960640529a60ad5198f29b59 AS shell
FROM apache/druid:0.20.0@sha256:7dd52427abd6941ed135d4a2b5005fcc29b4b6503682f686ee902dc7990eea1c
USER root
# Apache's vendor image downloads robxu9/bash-static 5.1.016-1.2.3.
# Only the command wrapper prerequisite is added; Druid/JRE/jars are unchanged.
COPY --from=shell /bin/bash /bin/bash
USER druid
