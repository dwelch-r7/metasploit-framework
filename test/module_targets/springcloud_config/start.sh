#!/bin/sh
set -eu
cd /lab/repository
exec java -Xms64m -Xmx256m -Xss256k -XX:MaxDirectMemorySize=32m \
  -XX:ParallelGCThreads=1 -XX:CICompilerCount=2 -XX:ActiveProcessorCount=1 \
  -Dloader.main=org.springframework.cloud.config.server.ConfigServerApplication \
  -cp /opt/app.jar org.springframework.boot.loader.PropertiesLauncher \
  --server.port=8888 --server.tomcat.max-threads=16 --server.tomcat.min-spare-threads=2 \
  --spring.profiles.active=native --spring.cloud.config.server.native.searchLocations=file:./ \
  --spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration,org.springframework.boot.actuate.autoconfigure.security.servlet.ManagementWebSecurityAutoConfiguration,org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
