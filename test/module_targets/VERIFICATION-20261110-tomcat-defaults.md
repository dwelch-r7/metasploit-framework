# Tomcat default Java runtime qualification, November 10

Current input hashes, exact counts and owned teardown establish **150 runtime
modules, 78 families and 1,069 functional cases**. The separate stock Java8
profile adds fourteen cases to the [NiFi checkpoint](VERIFICATION-20261110-nifi.md)
without adding already-qualified module names. The full campaign remains
incomplete; retained failures stay in the [deferred index](DEFERRED.md).

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb tomcat_java8
TOMCAT_JAVA_SPAWN=0 bundle exec ruby tools/dev/run_module_target_tests.rb tomcat
```

The [Java8 guide](tomcat_java8/README.md) uses genuine digest-pinned
Tomcat9.0.123/Temurin8u504 and the released metasploit-payloads2.0.257. It leaves
Spawn unset, checks the actual factory default2 and packaged SDK hash, and
preserves the vendor's actual JDK_JAVA_OPTIONS. No launcher, SDK, owning module,
shared library, project dependency or timeout changes.

## Native controls and results

The same real generated Servlet WAR and SDK bytes produce four callbacks in
four calls on stock Java8, but one in four on stock Java17. Removing only the
vendor JDK_JAVA_OPTIONS makes Java17 produce four callbacks, as does explicit
Spawn0 in the original environment. The actual variable contains seven
--add-opens flags; Docker Config.Env alone misses this runtime state.
JAVA_TOOL_OPTIONS is absent. The two images have identical catalina.sh,
setclasspath.sh and catalina.jar bytes. Actual Java17 child traces retain
EPIPE/SIGPIPE on the startup diagnostic written to closed stderr. These are
native callback observations, not claimed Meterpreter sessions.

Native Manager authentication, genuine JSP shell controls, deployment/removal,
version and file restoration add52 CLI and30 HTTP records. One initial native
script used an incorrect relative require path and stopped before payload
execution. Its source, logs and successful teardown remain preserved as setup
failure. No module verdict is inferred from it.

| Current profile | Invocation | Cases/failures | RSpec seconds | Current inputs |
| --- | --- | ---: | ---: | ---: |
| Stock Java8, unset/default Spawn2 | `20261110T055320-c7b4e8` |14/0|173.837214|39/39|
| Stock Java17, explicit Spawn0 | `20261110T060109-395999` |14/0|148.120512|37/37|

Both finish naturally with zero pending/outside errors and passing cleanup.
Each covers accepted/rejected login/check, both Manager APIs, automatic/explicit
Java targets, JSP shells, Java Meterpreter and Linuxx86 commands, with repeated
state-changing paths. Each opens AND uses12 real sessions, requiring12 fresh
native session proofs and4 executable proofs. Their union has42 current inputs.
They start independent actual consoles with read prompt, isolated returned BOOT
and both fresh parsed atomic metadata files. No metadata is injected between
invocations. Parent imports preserve complete raw commands, revision and paths.

The new Java8 profile checks original Tomcat temporary contents and absence of
SDK JVMs after each session. Six observed spawn directories disappear naturally,
all12 process checks are empty, and the original safeToDelete.tmp-only listing
returns. No operator removes an SDK artifact. Both profiles reject actual module
cleanup warnings and restore Manager/app-file state. Recursive child-/tmp and
long-term JVM classloader collection are not qualified. Both retain immediate
undeploy thread warnings; Java8 has18 and no SEVERE/ERROR line.

## Evidence and limits

The unchanged worker export is
`/Users/dwelch/.codex/reports/tomcat-java8-default-spawn-20261110-0f6526b2f25`.
Parent re-reads all311 entries in SHA256SUMS, whose SHA-256 is
`93cb2d7625faa4966736bb6082c61498014ab9ce50d0afdcb580cd484351a4f1`,
and verifies45 current source files. Both entire invocations are copied and
byte-checked; each has52 regular files including reproducible build inputs.
Independent parent inspection confirms all10 recorded containers and4 networks
absent across failed setup, native controls and both final runs; no volumes exist.

Parent RuboCop passes the changed Ruby spec; explicit selected dry discovery
passes14 examples and excluded discovery passes7 ancillary examples. The initial
untagged dry command selected only those7 ancillary examples and is retained
separately. Module docs keep exactly17/42 inherited warnings with identical
normalized diagnostics and unchanged human content. No full local RSpec suite
was run. All22 parent checksum entries are sealed at
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-f408ca64704`,
manifest SHA-256
`4aaf2d803ef29b3edab341b22f492b8f8d44b3f584457bcb02f80944ce1fb9c6`.

Stock Java17/defaultSpawn2 remains a demonstrated runtime/SDK limitation.
Windows, other Java releases, other Tomcat families and every JVM lifecycle
remain unqualified. Historical investigations and candidate SDK changes remain
separate; this passing Java8 profile does not establish a Java17 SDK fix.
