# Genuine Apache Spark targets

These disposable Linux amd64 targets use official Apache Spark binary archives,
verified against Apache's SHA-512 publications, on a pinned Temurin8 image. The
archive URLs/hashes are in `provenance.json`; no binary is committed. Docker
builds the harmless native Java driver from `NativeProof.java`.

Use the real vendor `bin/spark-class` entrypoint. It supplies the Scala environment
needed by standalone driver launchers; direct Java startup can display a healthy
UI while actual submitted drivers fail. Docker init reaps exited descendants; observations read the actual Java daemon
environment rather than assuming it is PID1. The application runs as UID/GID1500.
Target-only Python3 supplies the command payload prerequisite. No Framework
library, SDK, payload launcher or dependency is replaced.

The ACL profiles are Spark3.2.1 affected, Spark3.1.3 also affected, Spark3.2.2
fixed, and Spark3.2.1 with ACLs disabled. Apache's corrected advisory explicitly
includes3.1.3; it must not be labelled a fixed release. See
[Apache security advisories](https://spark.apache.org/security.html).

The REST profile explicitly enables standalone submissions on3.2.1 and includes
a real Worker. This is an enabled/disabled configuration boundary, not a claim
that a particular release fixes all unsafe REST configurations. The independent
native driver uses the same master property accepted by the module and must
actually write a fresh identity proof twice, with FINISHED driver status.

A real Apache gateway applies Basic authentication and strips `/spark-ui/` or
`/spark-rest/`. Its public fixtures are module-test-user/module-test-password.
Unrelated Apache and a published but closed REST endpoint provide negatives.
All host ports bind to random127.0.0.1 ports. The ordinary owned bridge does not
claim outbound filtering. There are no privileged services or host sockets.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb spark_ui spark_rest
```

Each profile first runs `native_probe.py` with independent CLI/HTTP observations.
It verifies archive versions, UID, actual vendor environment, real group-mapping
execution/refusal, Basic policy and prefix routing. Missing routes can still
execute because Spark's authorization filter runs before routing; the native
proof establishes this rather than assuming a negative. The REST gate requires
a registered Worker, actual completed Java drivers, proof bytes/owner and real
API version documents. Native command and HTTP transcripts are retained.

The functional corpus is initially unqualified until a strict runner result has
its expected count, no failures/pending/outside errors, current inputs and owned
teardown. Native controls and dry discovery alone do not qualify a module.
The selected paths cover check, exact commands, Python shells, Linux x64
printf/curl delivery, x86 command execution and actual Java sessions, with repeats
and bounded file/process/resource observations. They do not qualify Windows,
ARM, Kerberos, arbitrary versions, full TLS behavior or every session API.

Spark naturally retains completed-driver history. A finished native driver is
not called a leak. The configured Worker cleanup removes finished driver working
files; snapshots distinguish those files, Java process state and /tmp contents.
Test proof removal is explicit operator restoration. Do not relabel that as
production cleanup, or erase unexplained application files to make a case pass.

The existing REST module reads an undeclared TARGETURI datastore override. Root
calls omit it. Non-root cases explicitly require and retain that known warning,
reject every other unknown option, and do not claim advertised/registered prefix
support. The REST module is passive: WfsDelay is not registered there. Tests
observe its real background jobs and discovered sessions through public APIs,
then require fresh command proofs; an immediate completion banner is insufficient.
