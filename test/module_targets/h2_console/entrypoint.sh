#!/bin/sh
set -eu
version=${H2_VERSION:?Set H2_VERSION}
case "$version" in 1.4.199|2.0.204|2.1.214) ;; *) exit 2 ;; esac
if [ "${1:-}" = health ]; then
  curl --fail --silent http://127.0.0.1:8082/login.jsp >/dev/null
  curl --fail --silent http://127.0.0.1:8083/login.jsp >/dev/null
  exit
fi
exec java -Xms32m -Xmx128m -XX:+UseSerialGC -XX:ActiveProcessorCount=1 -cp ".:vendor/h2-$version.jar" Bootstrap
