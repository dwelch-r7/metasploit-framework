# Genuine legacy ActiveMQ FileServer lab

Run `bundle exec ruby tools/dev/run_module_target_tests.rb activemq_fileserver`
from the Framework root. Native preflight and Framework outcomes are recorded
separately. This family uses the shared `../activemq_legacy` source recipe,
pinned Temurin 8 amd64/JDK 1.8.0_412 and signature/checksum-verified Apache 5.11.1
and 5.14.0 archives. Public fixture credentials are `admin:admin` and `user:user`.
Ports publish randomly on 127.0.0.1; no operator service is used.

The [Apache advisory](https://activemq.apache.org/security-advisories.data/CVE-2016-3088-announcement.txt)
identifies removal of FileServer in 5.14.0 and default disabling since 5.12.0.
The genuine default policies matter: 5.11.1 FileServer PUT/DELETE accepts anonymous
and invalid credentials for the tested text-file paths. JSP-suffix PUT and
API/admin JSP execution require valid Basic auth, as does the installation-path
page. Both vendor admin and user roles are accepted.
The fixed broker still serves its real admin application and JMS service.

The FileServer-only launch clears `JAVA_TOOL_OPTIONS` before the actual vendor
launcher. The existing `ACTIVEMQ_OPTS` retains the broker CPU/memory bounds.
The packaged Java payload loader immediately closes respawned JVM output pipes;
the JVM's startup message for `JAVA_TOOL_OPTIONS` makes that child exit 141.
Independent same-JAR/original-JSP and source-visible child-process controls
reproduce this and succeed when only that variable is removed. This is a fixture
correction; the shared recipe and reader targets are unchanged. Native gates
verify the actual broker environment and execute its genuine ELF32/i386 loader.

Repeated custom names exercise new JAR resources at the same pathname. The JSP
closes a supported loader after SDK main; no global cache setting or shared Java
payload code changes. [Native capture provenance](../../../spec/file_fixtures/modules/exploits/multi/http/apache_activemq_upload_jsp/README.md)
distinguishes same-path stale-resource failures, distinct paths, closed loaders
and actual generated-JSP SDK-main controls. Java 7+ exposes the Closeable API;
older JVMs keep prior API behavior and remain unqualified here. Temporary SDK
state must match exactly, including after repeats. Callback counts alone cannot
pass the suite, and failure residue is never silently operator-deleted.

Native controls verify actual versions/JMS round trips and removal, real
PUT/MOVE/JSP compilation, uploaded JAR byte hashes and ProcessBuilder proof under
the broker JVM/user in both API/admin paths. The proof JAR has visible source;
it does not replace any target API, servlet or Framework handler. Moved paths,
including the module's doubled separators, are checked through the real
filesystem. Failed auth cannot execute that JSP. The fixed FileServer methods
and unrelated genuine Apache HTTP path return 404. App-file restoration is exact.

Nine Framework examples exercise two executions each for Java Meterpreter,
Java command shell, Linux x86 Meterpreter and Linux x86 command shell; default
and custom JSP names, API/admin paths, AutoCleanup true/false and the accepted
user role. Real session commands must create an owned proof. Header-only Framework traces retain
actual request paths and response status without dumping binary payload data.
After each production invocation, passive file receipts retain any surviving
upload bytes before fixture restoration; they do not wrap or delay callbacks. Uploaded web files,
payload temporary files and handlers must be restored; deliberately retained
AutoCleanup=false files are checked before fixture removal. Fixed, incorrect
credentials and unrelated targets must not claim execution or create state.

The genuine JDK and libc6-i386 are target dependencies for these declared Java
and Linux x86 paths. No project gem or simulated vulnerable response is added.
The normal application JSP compiler caches remain managed by Jetty; tests do not
wipe arbitrary compiler files. Known fixture paths are restored only after the
assertions and all captured failures remain failures.

Windows and the separate Windows traversal modules, other architectures,
TLS/IPv6, other releases and alternate payload transports remain unqualified.
This reusable suite must pass its own native and strict operator-output gates;
healthy containers or an HTTP status alone do not establish module success.
