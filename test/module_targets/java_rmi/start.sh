#!/bin/bash
set -euo pipefail
source /lab/settings.sh
mkdir -p /runtime
role="${LAB_ROLE:?}"
case "$role" in open|guarded|enabled|empty) ;; *) exit 2 ;; esac
agent=()
if [[ "$role" != empty ]]; then
  agent=(-Dcom.sun.management.jmxremote.port="$LAB_REGISTRY_PORT" -Dcom.sun.management.jmxremote.rmi.port="$LAB_OBJECT_PORT" -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.local.only=false)
  if [[ "$role" == guarded ]]; then
    umask 077
    printf '%s\n' 'controlRole module-target-jmx-password' > /runtime/jmx.password
    printf '%s\n' 'controlRole readwrite' > /runtime/jmx.access
    agent+=(-Dcom.sun.management.jmxremote.authenticate=true -Dcom.sun.management.jmxremote.password.file=/runtime/jmx.password -Dcom.sun.management.jmxremote.access.file=/runtime/jmx.access -Dcom.sun.management.jmxremote.password.toHashes=false)
  else
    agent+=(-Dcom.sun.management.jmxremote.authenticate=false)
  fi
fi
loading=()
if [[ "$role" == enabled ]]; then
  printf '%s\n' 'grant { permission java.security.AllPermission; };' > /runtime/all.policy
  # Deliberately weak, documented vendor settings; no JRMP handler is patched.
  loading=(-Djava.rmi.server.codebase="http://enabled:$LAB_HTTP_PORT/probe.jar" -Dsun.rmi.loader.logLevel=VERBOSE -Djava.security.manager -Djava.security.policy==/runtime/all.policy -Djava.rmi.server.useCodebaseOnly=false '-Dsun.rmi.transport.dgcFilter=*')
fi
exec java "${JVM_LIMITS[@]}" "${JDK_EXPORTS[@]}" -Djava.rmi.server.hostname="$role" "${agent[@]}" "${loading[@]}" -Dsun.net.httpserver.maxReqTime=2 -Dsun.net.httpserver.timerMillis=500 -cp /lab/classes Main
