# Log4Shell header execution verification — 2026-11-12

## Summary

`exploit/multi/http/log4shell_header_injection` is qualified for its Automatic
Java and Linux command targets in the real-library environment below:
**30 examples, 57 public module calls, zero failures, pending cases or
outside-example errors**. Twelve sessions and eight exact command executions
have independent target proof. Windows and vendor-product deployments remain
unqualified. The campaign reaches **215 qualified modules, 206 profiles and
2,134 functional examples**. Registration covers 217 sources; 287 documented
container hints remain pending and no review is stale.

The production owner and guide are unchanged, including human Scenarios. The
owner SHA-256 is `43bed302c898459843711b65e599b001181a96442ea10fe0207b6aad0b316cad`. The tested
commit is `7181ed47320c76052960542ed26103c770784873`.

| Profile | Examples / failures | Owning sessions | RSpec duration |
|---|---|---|---|
| log4shell_exec_remote | 10 / 0 | 10 | 317.153 s |
| log4shell_exec_no_codebase | 10 / 0 | 2 | 274.185 s |
| log4shell_exec_fixed | 10 / 0 | 0 | 167.200 s |

All final profiles ran serially in `20261112T151654-5f3802`. Each has 78 pinned
current inputs, 82 distinct across the matrix. The manager and independent
observer both exited zero. A live cold prompt, BOOT and two fresh metadata
snapshots were verified for the first console; subsequent profiles used only
that invocation's verified seed. No manual cache was supplied.

## What looks good

The target reuses the unchanged genuine Log4j HTTP sink and adds actual
Commons Beanutils 1.9.2, Collections 3.1 and Logging 1.2. Vendor bytes, code sources,
implementation versions and the Temurin 1.8.0_412 runtime are independently
verified. Maven publisher checksums informed the catalogs; every build enforces
SHA-256 and size. The JDK/build images are digest-pinned. All new native classes
and serialized proof graphs compile from included source; no generated binary
is committed.

Each profile first performs independent native controls, before any owning call.
A temporary Python LDAP/HTTP oracle inside the Framework container serves only a
benign ObjectFactory JAR and a source-built Beanutils graph. Actual Java execution
writes controlled process-identity markers matching the application JVM. Raw BER
requests/responses and served-JAR hashes remain captured. The oracle's original
process exits zero and its listeners close. These controls prove that old Log4j
with URL codebases enabled executes both paths, URL blocking stops the remote
factory while preserving the local gadget path, and patched Log4j executes neither.
The serialized-data prerequisite is explicit, rather than assumed for other apps.

The final functional matrix covers explicit and discovered headers, GET/POST,
checks, enabled/disabled AutoCheck, configuration refusal and an unlogged endpoint.
Every session and command case repeats. Delivery covers Java shell, default
spawned Java Meterpreter, embedded `Spawn=0` Meterpreter, and Linux Bash/generic
command payloads. Sixteen unsuccessful Java session attempts on blocked/patched
profiles and patched Linux attempts are verified as negatives by native file,
public session and SQL state; no session counter alone establishes success.

All twelve actual sessions perform public RPC/file operations with per-run
markers, target-native ownership, peer identity, kernel PID birth identity and
actual SQL records. Fresh remote responses immediately precede shutdown. Ten
child processes exit; two embedded Meterpreter runs preserve the same application
JVM and release their callback sockets. Host sessions disappear, SQL rows close,
proof files are removed, and active callback sockets are absent afterward.
The application metadata remains unchanged. Eight command executions produce
exact file bytes; patched controls leave no file and no session.

Cleanup is checked before harness recovery: public session/job vectors, LDAP,
HTTP and payload listeners, and callback sockets must already be empty. No
`fallback-cleanup.jsonl` is created. The shared `Console#reset` still issues its
normal bulk commands after each example; all sixty commands are independently
verified to follow already-empty session and job vectors. They close no active
object and cannot supply the asserted cleanup result.

Three containers run at a time, capped at **1,024 MiB, 1.5 CPUs and 416 tasks**:
target 256 MiB, Framework 640 MiB and PostgreSQL 128 MiB. Memory/swap allocations
match and no container is privileged. Native/final cgroup checks show zero OOM
or PID-limit events. All 24 final parent absence queries pass. Native labs have
32 additional exact cleanup queries; retained baseline and failed-fixture runs
have 24 and 16 respectively. No anonymous volume is hidden by the label-only
inventory: actual container mounts are checked as well. Docker is empty.

Both Ruby files pass strict RuboCop; the tagged dry run selects exactly ten
cases per profile. No full RSpec suite was run. Tests keep a 20-second HTTP
control, then use the registered two-second receive option with the same
three-second staging grace to avoid unnecessary waits on blocking Java replies.
The cold trusted profile records 317 seconds versus 447 in the retained baseline;
no execution or shutdown case was removed.

## Concerns

This is generic HTTP exploitation of genuine vendor libraries with explicit
configuration. It does not establish Windows, a particular Struts/Solr/vCenter
installation, every Java/Log4j release, other gadget chains, authentication modes
or IPv6. JVM URL-loader temporary JAR caches remain confined to the target's
throwaway filesystem and disappear at container teardown.

Initial failures were investigated as harness/setup faults, with no production
module defect established: a host-only path was passed to container Python, an
RSpec matcher was misspelled, and an overly broad HTTP-journal assertion rejected
a response-write `Broken pipe` after completed Java execution. That exact event
is retained and admitted only after real RPC proof, successful shutdown, native
process/socket closure, and unchanged application metadata. Other errors remain
failures. Source review also corrected an assumption that default Meterpreter
was embedded; both its default spawned path and explicit embedded path are tested.

One unrelated transient container stopped a native profile before startup; its
owner/image was not identified. It was later absent and the unchanged fixed-only
native retry passed. This is a resource/setup interruption, not a module verdict.
The cleanup guard separately removed observed unrelated tool containers.

The earlier 30-case baseline passed but checked some listeners after helper
recovery. It is retained as a baseline, not used to waive current fingerprints
or the final pre-recovery audit. Failed inputs/captures remain separately sealed.
Existing Druid, Superset RCE-owner and WordPress-admin exclusions remain unchanged.
CI belongs to the published commit and is recorded separately. No PR was created.

## Suggestions

Use [the target instructions](log4shell_execution/README.md) for the serial
reproduction command and source/dependency prerequisites. Keep native proof before
Framework calls and preserve the already qualified scanner target inputs.

Next, evaluate the real UniFi Network Application target named by its module
guide. Its images can contain backported fixes, so establish actual loaded
logger/gadget bytes, initialization/Mongo state and native callbacks before
version/check or execution claims. This is currently source review only: no
UniFi image has been pulled, no target started and no module verdict assigned.
Keep its Windows/macOS paths separate and preserve human Scenarios.

Private immutable evidence: `/Users/dwelch/.codex/reports/log4shell-execution-verified-20261112` has 476 manifest entries,
82 distinct input files and SHA-256
`083afa2119705ba7d49b49c2ceb9dac85d30a563d73a8053aee2260c5903d2a7`. Every file was independently copied and all hashes,
read-only modes and inode/link counts were checked. Separate baseline and failure
bundles preserve their exact inputs and observed errors. Captures include
transient lab addresses and stay outside the public repository.
