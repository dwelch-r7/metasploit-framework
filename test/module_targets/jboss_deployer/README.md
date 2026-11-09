# JBoss Java deployment targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb jboss_deployer
```

This family reuses the genuine, checksum-pinned AS 4.2.3.GA distribution,
Temurin 8u412 runtime, open/legacy/secured management policies, native BSH and
repository controls, and vendor deployment registry described in the
[management lab](../jboss/README.md). No additional target implementation or
simulated deployment endpoint is used.

The untouched vendor `inspectMBean.jsp` cannot compile against Java 8 with the
packaged old Eclipse JDT (`CharSequence` resolution fails). This session-only
profile uses Jasper's documented Ant/javac compiler option, with source/target
1.5 and forked JDK 8 javac. Apache Ant 1.10.15 is downloaded from its official
archive with publisher SHA-512 verification; only its runtime jars are shared
through a project-owned volume. The vendor servlet, inspector JSP, JBossWeb jar
and original JDT jar remain unchanged. The management family's default compiler
profile is untouched. See the [Jasper compiler documentation](https://tomcat.apache.org/tomcat-6.0-doc/jasper-howto.html).

A separate native preflight hashes those original vendor files, verifies the
actual Ant version and compiler settings, and compares both GET and POST HTTP
inspector fields with the vendor CLI's live OS/architecture/Java attributes
before any module runs. This prevents a compiler/setup error from being
classified as an automatic-target module failure.

The 12 examples exercise the BSH and DeploymentFileRepository exploits through
direct POST, GET stagers, legacy HEAD stagers, and authenticated POST. Java
Meterpreter and Java command-shell payloads use default Spawn=2. Automatic Java
selection on Linux amd64 and explicit Java Universal selection are covered.
Each positive path requires two fresh sessions, a fresh target file created
through the session with native owner proof, and restoration of both the WAR
deployment tree and live vendor web-module registry. Wrong credentials and
unrelated HTTP must not create a session or upload an application.

Native Windows and Linux x86 payloads, other AS/EAP/JDK releases, TLS, alternate
JMX context paths, MainDeployer remote archive callbacks, serialized invoker and
Remoting paths, Seam applications, and post credential gathering are outside
this profile. Benign native deployment is a setup gate; a strict session result
is still required. Inspect the run's exact result, captures and cleanup before
treating this family as qualified. Failed assertions precede explicit operator
fallback cleanup, so fallback cleanup cannot make a failed module pass.

The disposable project's HTTP ports bind only to host loopback. Framework and
reverse listeners stay on the internal Compose network. The
[shared guide](../README.md) describes retained source hashes and teardown.
