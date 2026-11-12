#!/bin/sh
set -eu
version=${LOG4J_VERSION:-2.14.1}
trust=${LOG4J_TRUST_CODEBASE:-true}
case "$version" in 2.14.1|2.17.1) ;; *) exit 2 ;; esac
case "$trust" in true|false) ;; *) exit 2 ;; esac
exec java -Xms16m -Xmx48m -Xss256k -XX:+UseSerialGC \
  -XX:MaxMetaspaceSize=48m -XX:ReservedCodeCacheSize=24m \
  -XX:MaxDirectMemorySize=16m -XX:ActiveProcessorCount=1 \
  -Dcom.sun.jndi.ldap.object.trustURLCodebase="$trust" \
  -Dcom.sun.jndi.ldap.object.trustSerialData=true \
  -Dmsf.module.target.value=module-target-property \
  -Dlog4j.configurationFile=/opt/module-target/log4j2.xml \
  -cp "vendor/log4j-api-$version.jar:vendor/log4j-core-$version.jar:vendor/commons-beanutils-1.9.2.jar:vendor/commons-collections-3.1.jar:vendor/commons-logging-1.2.jar:." ExecutionBootstrap "$@"
