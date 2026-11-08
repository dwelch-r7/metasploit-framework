# Tomcat Manager target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb tomcat
```

The lab reuses `test/tomcat/Dockerfile` with pinned Tomcat 9.0.123 and Java 17.
Public fixture credentials `tomcat` / `tomcat` have manager GUI and script roles.
Native curl authenticates to the real Manager server-info endpoint before
Framework runs; independent HTTP assertions also check rejected credentials.

The suite tests login, authenticated and rejected checks, HTML multipart and text
API WAR deployment. Java Meterpreter and JSP command-shell payloads must open real
sessions and execute a command, with two consecutive exploits per delivery path.
Java Meterpreter uses the explicitly configured `Spawn=0` in-process profile;
the module/payload defaults are unchanged. The default `Spawn=2` profile has an
intermittent no-session failure in the bundled payload's Java spawning path.
Same-JVM native controls and strace captured a Java17 startup diagnostic writing
to an already-closed stderr pipe and dying with SIGPIPE. An external source fix
candidate passed repeated sessions but still needs thread/lifecycle and broader
qualification in metasploit-payloads. To reproduce the released-payload diagnostic:

```sh
TOMCAT_JAVA_SPAWN=2 bundle exec ruby tools/dev/run_module_target_tests.rb tomcat
```

Keep its failures separate from passing `Spawn=0` qualification. Immediate WAR
removal also broke class loading for in-process payloads; the module cleanup
lifecycle now keeps deployment available through payload bootstrap.
The application's manager list and deployment files must return to their initial
state after each exploit. Both Manager APIs also execute Linux x86 command
payloads twice, with a fresh native file proving each execution and checks that
temporary executables disappear. Windows native targets remain unqualified.

The Framework console runs inside the same Compose network, using the repository
Dockerfile and entrypoint. Reverse listeners have no published ports. Only the
target's random host loopback HTTP port is published for independent probes.
See [the shared guide](../README.md) for evidence and cleanup.
