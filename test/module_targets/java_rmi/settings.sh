#!/bin/bash
# Shared JVM budgets, SDK exports and protocol ports for the genuine JVM lab.
export LAB_REGISTRY_PORT=1099 LAB_OBJECT_PORT=1100 LAB_MULTI_PORT=1119 LAB_ECHO_PORT=1120 LAB_HTTP_PORT=8180
JVM_LIMITS=(-Xms16m -Xmx48m -XX:+UseSerialGC -XX:ActiveProcessorCount=1 -XX:MaxMetaspaceSize=64m -XX:ReservedCodeCacheSize=32m)
JDK_EXPORTS=(--add-exports=java.rmi/sun.rmi.server=ALL-UNNAMED --add-exports=java.rmi/sun.rmi.transport=ALL-UNNAMED --add-exports=java.rmi/sun.rmi.transport.tcp=ALL-UNNAMED)
