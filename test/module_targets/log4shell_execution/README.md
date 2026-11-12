# Log4Shell header execution target

This separate target uses the genuine Log4j HTTP sink from `log4shell_http` and
adds the actual Commons Beanutils 1.9.2, Collections 3.1 and Logging 1.2 libraries
required by CommonsBeanutils1. The scanner's qualified files are unchanged.
Every vendor JAR is downloaded from a fixed Maven URL and checked against its
catalogued SHA-256 and size; publisher SHA-1 checksums were independently checked
when selecting the artifacts. Both build and JDK images are pinned by digest.
All added native classes and payload graphs build from the included Java source;
no generated JAR, serialized object or binary is stored in the repository.

Three profiles select Log4j 2.14.1 with URL codebases enabled, the same library
with URL codebases disabled, or patched 2.17.1. All explicitly permit serialized
LDAP data for this controlled gadget-chain target. These are distinct Java
configuration prerequisites, not defaults assumed for other applications.
The same live target JVM reports the loaded gadget-library code sources,
versions, process identity and serialization flag before starting the HTTP sink.

Before any owning exploit call, `native_probe.py` starts an independent Python
LDAP/HTTP oracle inside the Framework container. It serves a benign ObjectFactory
JAR and a source-built Beanutils graph. The remote factory and translet write
only controlled process-identity markers. Native checks compare those markers
to the actual HTTP JVM PID, preserve real LDAP request/response bytes and HTTP JAR
hashes, and remove the markers. URL blocking must stop remote-class execution
while preserving local gadget execution; patched Log4j must execute neither.
The temporary oracle is shut down and its original process is awaited.

The functional suite exercises real checks, explicit and automatically discovered
headers, GET/POST, enabled/disabled AutoCheck, remote Java shell/Meterpreter and
Linux generic/Bash delivery. Every execution case repeats. Public session RPC
writes per-run proof; native file/PID observations and database rows verify it.
Java Meterpreter shares the application JVM, so shutdown must preserve the JVM
and release its callback socket; command-shell child processes must exit.
Missing-header configuration and unlogged endpoints are negative controls.
Artifacts record HTTP input, SQL state, native counters and session lifecycle.
A failing case remains unclassified until setup, payload and owner evidence agree.

Run profiles serially with the guarded launcher:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb log4shell_exec_remote log4shell_exec_no_codebase log4shell_exec_fixed
```

Each profile has three containers, capped at 1,024 MiB, 1.5 CPU and 416 tasks:
target 256 MiB, Framework 640 MiB and PostgreSQL 128 MiB. Swap equals the memory
allocation. Only random loopback HTTP is published; LDAP and payload listeners
stay on the temporary internal network. Fresh runs own a separate console and
reporting database; the launcher tears the Compose project down afterward.
JDK URL-class-loader temporary JAR caches are confined to the target's temporary
filesystem and disappear at teardown. This harness does not qualify Windows,
other gadget chains, arbitrary Java versions or a particular vendor application.

Sources:

- [Owning module documentation](../../../documentation/modules/exploit/multi/http/log4shell_header_injection.md)
- [Apache Log4j security advisories](https://logging.apache.org/security.html)
- [OpenJDK 8u412 LDAP trust flags](https://github.com/openjdk/jdk8u/blob/jdk8u412-b08/jdk/src/share/classes/com/sun/jndi/ldap/VersionHelper12.java)
- [Original CommonsBeanutils1 graph](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsBeanutils1.java)
- [LDAP BER protocol, RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html)
