# Apache Druid sampler targets

These reusable profiles use genuine Apache Druid distributions with PostgreSQL
metadata storage, ZooKeeper, and a combined coordinator/Overlord. They qualify
sampler operations, rather than a Broker/Historical query-serving cluster. All
application releases, toolchains, database and frontend images are digest pinned.
No project gems or SDK changes are required.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb druid_js druid_jndi druid_sessions
```

The command profiles contain fifteen JavaScript and fourteen Kafka/JNDI cases;
the separately bounded [session profile](../druid_sessions/README.md) adds five
real delivery cases.
Each check and command case runs twice. A module exit or HTTP status alone is
insufficient: native preflight samples three actual rows, verifies the real
Overlord leader and metadata tables, and independently creates exact marker
bytes as UID/GID 1000 on the affected release. Fixed and disabled controls must
leave the marker absent. Test-created files are captured, removed and their
previous inventory restored. The session profile requires two usable sessions per case, actual target PIDs,
exact remote proof bytes and graceful remote PID disappearance before fallback
cleanup. Command-only profiles do not imply session coverage.

## Releases and prerequisites

- `druid_js`: official 0.20.0 and 0.20.1, both with JavaScript explicitly disabled.
  The [Apache advisory](https://www.openwall.com/lists/oss-security/2021/01/29/6)
  identifies 0.20.1 as the fix for CVE-2021-25646. The test uses the injectable
  empty property only in the affected native control. Explicitly enabling the
  JavaScript feature on a fixed release would be a different policy.
- `druid_jndi`: official 0.20.0/Kafka 2.6.0/JRE 8u265 and official 26.0.0/
  Kafka 3.4.0/JDK 11.0.18. The
  [Kafka advisory](https://kafka.apache.org/cve-list/#CVE-2023-25194) and tagged
  Kafka 3.4 source identify the default rejection of `JndiLoginModule`. Actual
  installed JAR hashes and JVM versions are retained by preflight. No Kafka
  broker, Internet callback or real account is used: JAAS lookup occurs before
  broker authentication. Runtime egress is isolated.

For JNDI, the target-only Dockerfile copies static Bash from the pinned official
26 image into the original 0.20.0 image. Apache's
[vendor Dockerfile](https://github.com/apache/druid/blob/druid-26.0.0/distribution/docker/Dockerfile)
uses `robxu9/bash-static` 5.1.016-1.2.3. This supplies Framework's Bash gadget
wrapper prerequisite; it changes no Druid/JRE/JAR/security setting. No opaque
binary is checked in. The base image has BusyBox wget and netcat, but lacks curl
and Python: the default curl, Bash (without this explicit addition), and Python
payloads are not implicitly qualified.

The JNDI native gate uses a genuine OpenLDAP server with its Java schema. A
source-built, fixed-marker Beanutils graph uses the actual unchanged target's
JARs, following the
[primary ysoserial object graph](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsBeanutils1.java).
Only the serialized object is delivered; no gadget JAR/class dependency is
installed on the target. Anonymous read permission is scoped to that test
object's DN, and the object is deleted after the native gate. Check observes an
LDAP lookup; that observation alone does not establish code execution. The
check retains the existing Vulnerable category for demonstrated JNDI injection,
as nearby Framework JNDI checks do. Its reason describes only the observed LDAP
search. The original fixture's Appears predicate was a policy disagreement,
not three production failures; that expectation correction is preserved
separately from the proven false code-execution wording. The exploit accepts a
post-deserialization HTTP 500 only after the current request both received a
search and generated payload-response attributes. AutoCheck's earlier lookup
cannot satisfy that evidence, and no response alone proves command execution.

## Paths, authentication and network isolation

The canonical default network is internal and contains Framework and Druid.
Only genuine Apache HTTP Server joins both this network and a separate public
bridge, publishing one random loopback-only host port. Its forward-proxy mode
is disabled. Native probes reach real Druid through fixed reverse-proxy routes;
Framework uses independently inspected internal endpoints. Every selected
endpoint, image/container ID, network ID and actual listener address is saved.
The runner's `ports: {}` deliberately avoids applying its single-network
endpoint assumption to this dual-bridge frontend. No runner changes, host
network mode, host socket, or public callback listener are used.

The runtime target catalog is read through Framework's public module API;
Linux is selected by name because this module's omitted DefaultTarget causes
Framework to insert Automatic before Windows/Linux. The ordinary global LHOST
is explicitly set to the inspected internal listener address: SocketServer's
advertised callback address intentionally gives LHOST precedence over SRVHOST.
Actual executing instances are audited without regenerating their payloads or
changing their commands, and their target/payload/callback fields are asserted.

CMD uses this family's Shellwords-escaped inline option, checked against the
real public Rex lexer. The earlier shared renderer lost existing backslashes
and produced an unmatched quote. No shared renderer is changed. Independent
native `/bin/sh -c` execution must create the same exact bytes and remove the
marker before Framework runs. The executing-instance CMD and JS method argument
are compared byte for byte, followed by comparison to actual HTTP/LDAP packet
data. This qualifies the documented escaped option route, rather than every
possible console quoting form.

Direct roots, a real proxy prefix, Apache Basic credentials, a valid user denied
by frontend policy, absent/wrong credentials, fixed releases, missing paths and
unrelated real Apache content are exercised. These are frontend authentication
policies, not a claim about Druid's built-in metadata roles. Apache's default
`Require user` denial returns 401 even for a valid viewer; a separate 200 proves
that viewer's credentials work on the permitted path. Fixture credentials are
public and disposable.

## Evidence and limits

Each canonical run retains the existing runner's current input hashes, native
CLI/HTTP records (including actual transmitted JSON), status/identity/metadata
proof, console transcripts, per-case file copies, listener checks and teardown.
The reused capture-client tool records actual affected-Druid HTTP/LDAP PCAPs in
its own network namespace. That capture scope excludes direct requests to the
fixed/unrelated services; their native receipts and actual console response
headers remain separate. Console HTTP trace is header-only because expected
Kafka exception bodies would collide with a generic console-helper assertion.

JavaScript sampling is at least once. On the examined 0.20.0 local passwd input,
`numRows:1` caused two harmless appends and `numRows:10` caused eight. Reducing
that number is not an exactly-once guarantee. Commands and callbacks can have
side effects more than once. Independent quiet marker execution may succeed
before the sampler returns an error; on the old Kafka path the native
serialized object executes before HTTP 500. Neither an HTTP error nor a failing
test automatically proves a module or fixture is correct.

The preserved exploratory controls include a legacy JSON-parser partial 200
serialization error and an accidentally shared ZooKeeper namespace that caused
a 307 redirect. Modern input-source JSON sampling and distinct profile namespaces
are required; these setup observations are not module verdicts. Windows, other
JVM/gadget combinations, built-in Druid roles, complete analytics clusters,
HTTPS and external brokers are not claimed. Session coverage is specifically
JS Unix netcat, wget x86 shell, authenticated prefixed wget x64 Meterpreter,
JNDI Bash and prefixed JNDI netcat. The JNDI target named Linux declares Unix:
its public compatibility check rejects Linux fetch adapters, so they remain
unqualified. The corrected original session baseline opened, used and cleaned
eight real sessions, with both JNDI cases failing only the module's erroneous
post-execution status. The earlier short readiness wait and dropped capture
packets were fixture limits, preserved separately from source behavior.
Human-written module Scenarios remain unchanged.
