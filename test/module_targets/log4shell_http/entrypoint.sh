#!/bin/sh
set -eu
version=${LOG4J_VERSION:-2.14.1}
case "$version" in 2.14.1|2.17.1) ;; *) exit 2 ;; esac
exec java -Xms16m -Xmx48m -Xss256k -XX:+UseSerialGC \
  -XX:MaxMetaspaceSize=48m -XX:ReservedCodeCacheSize=24m \
  -XX:MaxDirectMemorySize=16m -XX:ActiveProcessorCount=1 \
  -Dcom.sun.jndi.ldap.object.trustURLCodebase=false \
  -Dmsf.module.target.value=module-target-property \
  -Dlog4j.configurationFile=/opt/module-target/log4j2.xml \
  -cp "vendor/log4j-api-$version.jar:vendor/log4j-core-$version.jar:." Target "$@"
