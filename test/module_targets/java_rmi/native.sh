#!/bin/bash
set -euo pipefail
source /lab/settings.sh
exec java --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED "${JVM_LIMITS[@]}" "${JDK_EXPORTS[@]}" -Djava.rmi.server.useCodebaseOnly=false \
  -Djava.rmi.server.codebase="http://empty:$LAB_HTTP_PORT/probe.jar" \
  -Dsun.rmi.transport.tcp.responseTimeout=5000 -Dsun.rmi.transport.connectionTimeout=5000 \
  -cp /lab/classes:/lab/probe.jar NativeProbe "$@"
