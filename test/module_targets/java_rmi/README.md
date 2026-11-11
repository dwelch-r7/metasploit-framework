# Deferred full Java RMI profile

The original eighteen owning cases and `manifest.deferred.yml` remain here for
historical-JVM investigation. This profile is excluded from automatic registration.
The Java RMI class-loading scanner is unqualified.

Real Temurin 17.0.21+9 native controls could not obtain the required DGC marker.
Even SecurityManager/AllPermission, `useCodebaseOnly=false`, a permissive DGC
filter and an explicit server HTTP codebase were insufficient. Modern vendor
[DGC dispatch](https://github.com/openjdk/jdk17u/blob/master/src/java.rmi/share/classes/sun/rmi/server/UnicastServerRef.java)
forces server-codebase use, and its restricted context denied SocketPermission
connect. Original client-annotation and server-codebase failures are retained in
[the verification report](../VERIFICATION-20261111-java-jmx.md). They do not
establish a defect in the unexecuted Framework scanner. A genuine historical
runtime remains pending; no vendor protocol handler is replaced to obtain a pass.

[Registry and JMX owners](../java_jmx/README.md) have a separate nine-case profile.
It uses the same readable Java source, pinned compiler image and native SDK
controls without claiming DGC execution. Generated classes/JARs remain inside
images. The full deferred topology would use five containers capped at
1,792 MiB/1.4 CPUs; the registered JMX topology uses four at 1,536 MiB/1.3 CPUs.
