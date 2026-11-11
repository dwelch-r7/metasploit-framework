# RocketMQ discovery verification — 11 November 2026

Later execution/session coverage is recorded in the
[execution checkpoint](VERIFICATION-20261111-rocketmq-execution.md). This report
retains its discovery-only scope.

The checkpoint is **197 qualified modules, 141 profiles and 1,555 passing
functional examples**. The new [RocketMQ lab](rocketmq/README.md) qualifies
`auxiliary/scanner/misc/rocketmq_version` and exercises the exploit's version
check. A confirmed response-parser crash is fixed. The exploit's execution,
automatic Broker-port selection, payloads, sessions and cleanup remain
unqualified; the broad module campaign remains incomplete.

## Real targets and bounded native controls

The genuine Apache RocketMQ **4.9.4** and **5.1.1** images each run their original
NameServer and Broker main classes. They share an address within each container,
and the Broker advertises its actual bridge address on **10921**, rather than
relying on the usual 10911. The launcher changes ordinary heap, thread-pool and
message-store settings; it does not patch server handlers or fabricate replies.

The pinned Linux amd64 manifests are
`79b41e2956de07c576949bedf8f9bc5eac9f1eeb72362b89ee2344219e5a46b1` and
`ea678fa94854010d27e1ae82fcb929ee02381e65751921fc188d4f8110065983`.
Root verifies both registry config digests and every vendor `rootfs.diff_ids`
entry against the corresponding actual runtime image's layer prefix. The target
images are `273c8fa4541b3c5e4da6179a626893ffa9efc152ed74b541d173ea2555451bc5`
and `88236ad53ae58f998fa833f73bd79e91afd44084158495a80d937672684a0097`.
The SDK probe compiles separately against each distribution's bundled jars with
Java 8 bytecode; its native Netty client supplies the protocol serialization.

Native controls before owning calls verify SDK/server versions, the real topic
route and Broker endpoint, server UID 3000, unchanged Broker PID and logical
configuration. A successful same-value update verifies the administrative API.
A fresh native SDK injection requires an actual command-created marker on 4.9.4
and no marker on 5.1.1 over a full 36-second schedule window. Both modified
configuration values are restored and the marker removed. A successful update
response alone is never treated as execution. Native snapshots after the cases
must retain the same route, logical configuration and Broker PID.

Three containers total **2,048 MiB/1.5 CPUs**: each target 640 MiB/0.25 CPU and
Framework 768 MiB/one CPU. All have a 256-PID cap, swap equal to memory and disabled
privileged mode. Only random loopback NameServer ports are published; Framework
connects over the single project bridge. No Docker volume survives teardown.
The separate successful native prerequisite run records memory/PID limit events
and memory OOM counters at zero; its target peaks are 230,506,496/351,752,192 bytes.
Those are that prerequisite run's observations, not final-profile peaks.

## Complete owning replay

Run **20261111T132540-9b544b**, source `e31c83dbe5fd9b671ae344a408c88689a3100a08`, passes **8 examples,
zero failures/pending/outside errors** in **156.300335 RSpec seconds**.
The actual manager and independent live observer both exit zero.

All sixteen owning calls execute their cases twice:

- Discover each real release's version and exact advertised Broker name/address.
- Classify 4.9.4 as Appears and 5.1.1 as Safe through the exploit's public check.
- Read the Broker's genuine unsupported-route reply without inventing route data,
  retaining its valid 5.1.1 version in both scanner and check.
- Handle refused connections without successful discovery, a vulnerable verdict
  or an operator-facing source backtrace; detailed exceptions remain logged.

The sixteen call-through helper observations contain eight normal 95-byte JSON
headers, four 138-byte error headers with no body, and four nil refused sockets.
These are real helper return buffers and console output, not packet captures.
Both full native controls and both after snapshots pass, with restored and
unchanged logical state. No session or database persistence result is claimed.

Root verifies all **45 current selected input hashes**, actual owning records,
SDK/version identities and restored state. The first real console prompt,
isolated BOOT and two fresh metadata snapshots are observed with no first seed.
Eight independent cleanup queries prove all three exact containers, the exact
network and project-label inventories absent; the global container list is empty.

The immutable **129-file** source/run/review package has manifest SHA256
`808dca0ab359ca5ff46592b8caca927faa9382cbc547571d3f9ed5278711442d`.

## Confirmed source defect and regression

The first owning run `20261111T131052-a4d8c3` passes six of eight cases, with
fourteen actual calls: each failed wrong-port case aborts its second iteration.
Both native before/after comparisons pass. The 142-byte Broker reply has a real
138-byte JSON header, code 3, version 435 and no body; the original parser splits
on a hardcoded 95-byte header marker and dereferences nil in both consumers.
Its actual manager exits 1; root's eight cleanup queries pass. The 122-file
failure/source package has manifest SHA256
`7f0e97101893d799bdacb36ad4afbc97708388ed33cbcaf63a9d155489d6b94a`.

The fix follows the upstream [header-length and serialization fields](https://github.com/apache/rocketmq/blob/rocketmq-all-4.9.4/remoting/src/main/java/org/apache/rocketmq/remoting/protocol/RemotingCommand.java#L141-L183),
parses the header and optional body separately, and preserves the version-only
error reply. Malformed/truncated/non-JSON-serialization replies return nil;
callers handle it. Impossible Java-int version values are rejected before the
version-table lookup. A braces-in-string case no longer splits valid JSON.
Expected connection refusals retain concise console output and detailed elog.

Original worker commit `5dd4cee7792e9ee7c1f24a3895bcd69133be431d` is imported as
`49cad32ae6d`. Three byte-exact captures have verified SHA256/provenance. The
identical 35-example suite has 20 failures before and zero after, including 28
RocketMQ cases and seven shared formatter checks. Root's normal invocation also
passes 35/0. Earlier isolated-loader failures are retained and explicitly
excluded from this comparison. The 55-file independently verified fix package
has manifest SHA256
`9c08539be4631c0da2a9dfb89142a1bc929f10dd2df03a8bcac6487f9283c5bd`.

## Setup failures retained separately

All of these have zero owning calls and actual terminal exit 1. They do not
establish module failures. Exact/project/global cleanup passes for each.

| Native run | Observed setup failure | Immutable manifest SHA256 |
| --- | --- | --- |
| `125833` / `125853` | Missing Framework Compose overlay, then a removed 5.1.1 SDK thread-setting method; neither creates runtime containers | `1afa2e1ca24c503adb757d528283e8ada9c3b6f29d3fbf6d2987181e14d9c770` |
| `130157` | Repeated third-JVM SDK health checks exceed 8 seconds; later fixed-target native-thread allocation failure | `5170d7964b51ee79d2c2ba0c70307909e18606958de3bf5bdbd9843076474fd7` |
| `130613` | Vulnerable control passes; fixed SDK route request fails before injection while PID-limit events occur | `cae7adc12aa505d662e485ebf0f53ffc254d26c769c4631b47c1107e03dd7a59` |

The final setup uses lightweight process/log/TCP readiness, ordinary smaller
thread pools and 256 PIDs, with unchanged CPU/RAM limits. A root Java-version
probe overlapped the last failed fixed preflight and added pressure; its exact
contribution to the closed-channel error is unproven. A separate successful
native run `130805` verifies both execution controls/restoration before any
owning invocation; seven root cleanup queries pass. Its 21-file package has
manifest SHA256
`0100911e5029ffa847afe1aeb0636b7eed714244a0a2376bb41a66554081183c`.

## Static checks and remaining scope

Changed Ruby has no new lint findings. Three existing library offenses and the
exploit's default-PAYLOAD warning remain; scanner/new specs/helpers are clean.
Scanner msftidy exits 0; exploit msftidy exits 2 for that same pre-existing
warning. Both module documents pass their checker, their human Scenarios are
byte-identical, and their lab links resolve.

Coverage is limited to these releases, IPv4, JSON serialization and ACL-disabled
services. Other version boundaries, authentication, IPv6, binary serialization,
transport fragmentation/length limits and all full exploit/session paths remain
outside this qualification. The inventory registers 199 sources, with 306
documented container hints pending, sixteen individual reviews and no stale
reviews. Registration alone is not a passing result. No PR is created.

## Review

**Summary:** The scanner's main discovery paths and a confirmed error-reply
crash are covered by real services, focused regression tests and a full replay.

**What looks good:** Native controls establish target identity and execution
behavior independently; source hashes, repeated calls and exact teardown agree.

**Concerns:** No new concerns remain within the qualified scanner scope. The
existing lint findings and untested exploit/session paths are explicit above.

**Suggestions:** Qualify the exploit's payload, session and restoration paths
separately before counting it as a working module.
