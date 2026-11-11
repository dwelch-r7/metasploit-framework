# Java registry and JMX verification — 11 November 2026

The checkpoint is **195 qualified modules, 139 profiles and 1,535 passing
functional examples**. The new `java_jmx` profile qualifies:

- `auxiliary/gather/java_rmi_registry`
- `auxiliary/scanner/misc/java_jmx_server`

The Java RMI class-loading scanner remains unqualified. Its original eighteen
cases and deferred manifest are preserved in `java_rmi`; the ordinary registry
and JMX results do not qualify its DGC execution path.

## Genuine target and resource limits

Three unchanged vendor JVMs provide anonymous JMX, password-protected JMX and an
empty registry plus a second registry with two real dynamic-proxy aliases.
Temurin **17.0.21+9** is observed in the native controls and target logs. The base
is pinned to `eclipse-temurin@sha256:057a0daec60e87c96571bf5c9c7792065bcb19e804d584cd37d4144038a35717`,
actual cached image `sha256:fee8cb4328cdfa329ad5e2d14266ab9f70132d533f7fab5ebb1dba45758d71c2`.
All three target filesystem-layer lists match and include that exact base.
Readable Java source and compiler commands produce the owned proof JAR inside
images; no generated binary is checked in or vendor protocol handler replaced.

The four-role topology totals **1,536 MiB/1.3 CPUs**: Framework uses 768 MiB/one
CPU, each target 256 MiB/one-tenth CPU. Memory swap equals each memory limit,
PIDs are bounded and privileged mode is disabled. Actual live inspection confirms
these limits and no OOM-killed container. Framework selects the internal network;
random host bindings use loopback. Only this project runs during the owner replay.

## Native controls and complete owning results

Before and after owning calls, real JDK SDK clients list/look up registry objects,
invoke the dynamic-proxy remote method, check actual MBean attributes, reject
anonymous/bad-password access to the guarded server and authenticate correctly.
Native MLet loading executes fresh marker code on the anonymous server; marker
bytes include the independently queried server PID. Both transient MBeans and
the owned file are removed. Before/after marker tokens differ, and the proof JAR
SHA256 is unchanged within the run. Payload classes are absent from the server
class path. The same explicit internal addresses are supplied to SDK and Framework
registry requests; returned object references retain their real service names.

Run **20261111T114710-404cc2**, source
`a36032f60148e74d8f29e4f74057c4042f601e91`, passes **nine examples with zero
failures, pending or errors outside examples**, in **140.174564 RSpec seconds**.
The actual manager and root observer exit zero. All eighteen owning calls have
separate records. Coverage includes:

- Repeated registry enumeration of anonymous and guarded JMX references.
- Both genuine dynamic-proxy aliases, including `quoted café`, and an empty registry.
- Anonymous JMX access, authentication refusals and an absent JMX binding.
- Genuine HTTP negatives for both owners, with no invented reports.

Ten service and two vulnerability reporting API calls have checked arguments.
These are call-through observations; SQL persistence is not claimed. Forty-eight
complete JRMP/HTTP read buffers are retained as base64. The observer records Rex
client peer arguments: numeric registry addresses and returned `open`/`guarded`
service names for object connections. These labels are not a packet capture or
an independent numeric socket-peer measurement.

Root verifies all **65 current selected input hashes**, native server identities,
returned references, reporting arguments and owned-state cleanup. The actual
first prompt, isolated BOOT and both fresh metadata snapshots are observed with
no first seed. Ten independent cleanup queries prove all four exact containers,
two networks and project-label inventories absent; global containers are empty.

The complete immutable **156-file** source/run/review package has manifest SHA256
`999ca6f05ee24c1d3e01166c9add16e078fdd8b1b090de2cf9b980b14fa53b87`.

## Confirmed module error and separate harness failures

The first native-passed owning run, `113952-378300`, has seven passing cases and
two failures. One is an actual module defect: an empty registry returns genuine
`java.rmi.NotBoundException`, which previously escapes discovery and aborts the
scanner. The other is a harness matcher rejecting the expected verbose
`java.lang.SecurityException` authentication diagnostic. Both native phases pass.
The original complete 140-file package is retained with manifest SHA256
`93d4313bfd3fcb46cc289eb938bf8b8251a8114f1c67f448de1a564fc14f93fa`.

A separate source-only worktree fixes the exact missing-binding exception, letting
the scanner use its existing disconnect/MBean-not-detected path. Other remote and
local exceptions still propagate. The identical focused spec has five examples:
two fail against the original source, all five pass after the fix. Root reviews
and imports commit `3085333d81f753bf79f497ebd6617fb704ed9983` as `a36032f6014`.
The independently verified 38-file source-fix package has manifest SHA256
`83ab45a0f04124c945dea33578ea1499c2ebd5ec927df49a889ab20e0906e32d`.
Root's normal spec invocation passes twelve examples, including seven shared
formatter cases. The local Java console adapter retains expected protocol
exceptions while still rejecting unhandled module failures, then the complete
nine-case owning profile is replayed successfully.

Earlier prerequisite failures are also retained, with zero owning calls:

| Run | Actual prerequisite result | Immutable manifest SHA256 |
| --- | --- | --- |
| `112602-9f0915` | Native client compilation accessed a package-private JDK method | `1e515144a217de5d3d34f863e911a9aad7f2e1694c0618daa78f067fd5d38439` |
| `112645-819ff6` | DGC marker absent; native control blocked all eighteen owning cases | `10a3ec83a79c3014aabbbfae6c96569613e837a4e1a06464cf79bad4139cf8a2` |
| `112914-3b7281` | Native DGC ClassNotFoundException retained; no execution proof | `47b0af01350840049e766517ce6affe6edc01f395222f02777587fe952c2542a` |
| Native `113248` | Client annotation present but modern DGC ignores it | `db6433d9ed8615821c1395e3d1ec8bf7238b27e94352dae725b0e15e9a89b0f7` |
| Native `113424` | Explicit server codebase still denied SocketPermission connect | `da4a8e634b06cba8687fe0be4ed3a3eb59977798ef1848751c859f3c1389ec06` |
| `113732-f5ae10` | SDK controls pass; harness wrongly compares a DNS address with the selected internal address | `1b0c98fa5ff68b72826362a6a75354f2959ca4013631a504d9a66353c3c14a9b` |

Each manager's actual terminal status and independent cleanup are observed before
the next runtime. The first build creates no containers; native-only diagnostics
use four targets without Framework. The two initial full-profile attempts use the
ordinary launcher with independent live limits; subsequent owning runs use the
shared guarded launcher. No failed prerequisite is classified as a module defect.

Modern [OpenJDK DGC dispatch](https://github.com/openjdk/jdk17u/blob/master/src/java.rmi/share/classes/sun/rmi/server/UnicastServerRef.java)
forces server-codebase use, and its
[restricted DGC context](https://github.com/openjdk/jdk17u/blob/master/src/java.rmi/share/classes/sun/rmi/transport/DGCImpl.java)
explains the observed denied connection. A genuine historical runtime remains
pending. No dispatch/filter replacement is used to make that prerequisite pass.

## Checks and remaining scope

Changed helpers/specs pass syntax and RuboCop; module msftidy passes. Root compares
the module's same 23 existing RuboCop findings with the base. Module-document lint
retains the same five existing warnings; human Scenarios remain byte-identical.
The non-ASCII case emits a JSON 2.x binary-string warning in observation logging;
its values are retained and the case passes. JSON 3.x behavior is unqualified.

Static inventory covers 5,179 files, including 4,622 module candidates, 555 payload
components and two supporting files. Registration covers 197 sources; sixteen
individual reviews have zero stale entries, and 308 documented container hints
remain pending. Registration does not establish functional success. Other JVMs,
JMX TLS, broader Unicode forms, DGC positives and SQL persistence remain separate.
The broad campaign remains incomplete; no full Framework suite or PR is created.
