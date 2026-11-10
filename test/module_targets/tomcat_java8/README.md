# Tomcat Manager with the default Java payload

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb tomcat_java8
```

This profile reuses the real Manager suite and `test/tomcat/Dockerfile`, using
the official digest-pinned Tomcat 9.0.123 image with Temurin 8u504. Tomcat 9
[supports Java 8 or later](https://tomcat.apache.org/migration-9.html).
The public fixture account `tomcat` / `tomcat` has the GUI and script roles.
It runs the vendor startup scripts without an environment adapter or SDK change.

The fourteen cases cover valid/rejected login and checks, HTML multipart and text
API deployment, automatic and explicit Java targets, JSP command shells, Java
Meterpreter, and Linux x86 command payloads. Each execution path runs twice,
requires a real session or independent command proof, and restores the Manager
listing and deployment files. Linux command paths also restore temporary files.
The default profile additionally requires the Java temporary directory to return
to its original contents and the spawned SDK JVMs to exit after each session.
Cleanup polling returns immediately when complete and has a ten-second wall
clock bound; it does not delete SDK artifacts to manufacture restoration.
Meterpreter leaves `Spawn` unset, uses its real default of 2, and requires the
packaged SDK identity recorded by the native controls. The console default,
native JVM version, original `catalina.sh` hash, and actual startup environment
are checked again during each invocation. No payload override is installed.

This is a separate runtime qualification from the existing
[Java17/explicit Spawn=0 profile](../tomcat/README.md). It does not repair the
released SDK's Java17 spawning limitation. Fresh native controls used the same
SDK class and byte-identical generated WARs on stock Tomcat 9.0.123:

| Native path | Java17 | Java8 |
| --- | --- | --- |
| Four calls from one JVM, default Spawn=2 and original startup environment | 1 callback | 4 callbacks |
| Four HTTP requests to the generated default-Spawn SDK Servlet WAR | 1 callback | 4 callbacks |
| Generated JSP shell WAR, two independent native command proofs | 2 proofs | 2 proofs |

The SDK controls only establish native transport callbacks; they do not claim
Meterpreter sessions. Java17 also produced four callbacks when only the native
control process's inherited `JDK_JAVA_OPTIONS` was removed, and four with explicit
Spawn=0. Both stock Tomcat processes exported the same vendor `--add-opens`
options. Java8 does not use that Java9+ launcher variable. The vendor scripts
and `catalina.jar` hashes matched across images. Earlier Java17 strace evidence
of startup stderr receiving SIGPIPE is retained separately, including its
unintegrated SDK candidate; no historical Spawn=0 result is relabelled.

Windows native targets and other Java runtimes are unqualified by this profile.
The shared guide describes [evidence and cleanup](../README.md). Human module
Scenarios remain unchanged.
