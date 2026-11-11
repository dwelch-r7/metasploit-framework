# Genuine JVM JMX/RMI lab

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb java_rmi
```

Five serial-owned containers are capped at 1,792 MiB and 1.4 CPUs. Four normal
Temurin 17 JVMs provide unauthenticated JMX, password-protected JMX, deliberately
enabled DGC class loading, and empty/multi-name RMI registries. Frame uses 768 MiB;
each target uses 256 MiB, one-tenth CPU and bounded JVM heap/metaspace/thread limits.

The standard JVM management agent and registry implementations handle JRMP. The
enabled role uses supported SecurityManager/policy, `useCodebaseOnly=false` and
`sun.rmi.transport.dgcFilter=*` settings. This is an intentionally weak
configuration, not a claim that the default JDK 17 is vulnerable. No vendor
protocol handler is replaced. HTTP serves only the readable lab proof JAR and
health endpoint. All Java sources and compiler commands are included; generated
classes/JARs live inside images, never as opaque checked-in payloads.

Before/after native Java SDK clients require real registry list/lookup/methods,
actual JMX attributes/authentication, native MLet marker execution, and native
DGC delivery with fresh marker/PID proof on the enabled role and absent markers
on defaults. Downloaded payload classes are absent from the server class path.
Transient MBeans/files are verified and removed. A returned exception alone is
not execution proof. Missing native controls prevent all owning calls.

Eighteen owning examples exercise three modules with repeats, default/enabled
class loading, authentication, dynamic proxies, empty/HTTP/closed negatives and
a mixed batch. Reporting methods and genuine vendor replies are observed with
call-through hooks. SQL persistence and other JVM versions are separate claims.
A configured profile is not passing qualification.
