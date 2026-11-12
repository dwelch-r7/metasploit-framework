# NetAlertX queued execution verification — 2026-11-12

## Summary

`exploit/linux/http/netalertx_rce_cve_2024_46506` is qualified for its Linux command
target on the exact protected 24.9.12/24.10.12 images below: **10 functional
examples, 20 public module calls, zero failures, pending cases or outside-example
errors**. Eleven owning sessions have real RPC, native process/file/socket and
SQL closure proof. The campaign reaches **218 qualified modules, 214 profiles
and 2,192 functional examples**. Registration covers 220 sources; 284 documented
container hints remain pending and no review is stale.

The production fix prevents checks/refused runs from writing settings and
preserves the complete original configuration during execution/restoration.
Final module SHA-256:
`cbb84a839e7bc8aa616c385b3fc6d7dc970d7eedd257b9210de701a41f5b25d9`.
The tested commit is `06cb89e264cd2d95609b35e7ea21f15a59b198d0`. Human module
Scenarios remain byte-exact; the guide adds lab/prerequisite/cleanup information.

| Profile | Examples / failures | Bash / Meterpreter sessions | RSpec duration |
|---|---|---|---|
| netalertx_exec_24_9_12 | 5 / 0 | 8 / 3 | 465.169 s |
| netalertx_exec_24_10_12 | 5 / 0 | 0 / 0 | 115.177 s |

All final profiles run serially in `20261112T181107-d1b164`. Each has 68 current
pinned inputs, 70 distinct across the matrix. The manager and independent
observer exit zero. The first console has an independently observed cold prompt,
BOOT and two fresh metadata snapshots; the second uses only the verified seed
from that same invocation.

## What looks good

[The execution lab](netalertx_execution/README.md) runs genuine vendor PHP/FPM,
NGINX, Python backend, cron and s6-overlay from digest-pinned amd64 images.
Runtime hashes verify 57 application/cron files per version. The existing
qualified file-collection component is reused without editing its inputs.

Native prerequisites precede owning module calls. Real migrations/configuration
import, wrong/correct login, settings/API updates and queued plugin execution
are checked. A harmless command writes the actual backend parent PID; native
ownership and observed process identities agree. The affected image executes
without authentication; the control rejects all three anonymous update/queue
requests, while authenticated execution succeeds. The complete native snapshot
is restored and the real cron-driven restart is awaited. A second independent
native run confirms configuration preservation and stable backend count.

The shipped s6/cron interaction produces two backend processes after restart.
The test retains that genuine behavior, rather than replacing the scheduler or
simulating a callback. Repeated queues can therefore open two sessions. All eleven
actual sessions are tracked: eight Bash and three default fetched Linux
Meterpreter. No session counter alone establishes success.

Every session performs public RPC/file proof with exact per-run bytes, target
ownership, peer identity, kernel process birth and the real database session ID.
A fresh response precedes shutdown. Native child processes terminate, SQL rows
close, active callback sockets disappear and proof files are removed. Fetched
executables are deleted. Both cleanup modes repeat; all twenty public calls
complete with the expected result on their respective profiles.

The source fix reads a complete original configuration through the real logs
endpoint and preserves it as opaque text through the vendor's raw settings type.
It evaluates no target data locally. Only the three execution assignments are
appended. Cleanup runs only after this instance attempted a write, restores the
original custom command/schedule and all unrelated assignments, and retains retry
state if restoration fails. It reports expected transport failures without raising
from cleanup. Unavailable, generic or potentially truncated snapshots fail before
any settings write; a whole-file size label also guards partial UTF-8 tails.

Native comparisons retain every original assignment, including authentication,
SMTP, subnets and inactive-plugin settings absent from API metadata. Thirty final
configuration comparisons pass. Active settings, empty cron queue, bounded backend
count and callback closure settle before the next run. CLEANUP=false deliberately
leaves only its three execution assignments changed; two explicit native restores
prepare subsequent iterations. No unexpected configuration recovery or fallback
session cleanup journal exists.

All twenty normal harness bulk reset commands follow already-empty job/session
vectors and close no active object. All sixteen final parent resource-absence
queries pass. Actual mounts show no anonymous volumes. Docker is empty.

Three containers run at once, capped at **1,024 MiB, 1.6 CPUs and 416 tasks**:
target 256 MiB / 0.4 CPU / 96 tasks, Framework 640 MiB / 1 CPU / 256 tasks and
PostgreSQL 128 MiB / 0.2 CPU / 64 tasks. Memory/swap limits match; none is privileged.
Runtime networks are independently verified internal-only, with no published
ports. This contains discovery defaults even if a defective update resets them.
Native HTTP runs in the target namespace; Framework uses its measured address
for actual TCP traffic. The vendor supervisor owns PID 1. Cgroup checks show
zero OOM or PID-limit events in all three roles.

The same focused 20-case regression suite produces **18 failures on the original
module and zero on the fix**, with identical seed/order and no pending/outside
errors. Initialization, AutoCheck, owner code and Rex HTML handling are real;
HTTP/storage, UI and payload bytes are explicit doubles. Genuine qualification
comes from the separate functional matrix above. Both new specs pass strict
RuboCop; syntax, tagged five-case dry run and documentation checks pass. No full
RSpec suite was run. The real minute-based cron cycle is retained, accounting
for much of the affected profile's duration.

## Concerns

The original functional baseline has seven failures across ten cases. A public
`check` and an AutoCheck-aborted run both invoke unconditional cleanup and replace
the application configuration with only three hardcoded fields. Actual captures
show removal of authentication, SMTP and discovery settings. Execution performs
the same destructive partial update, and cleanup resets factory values rather
than the actual original command/schedule. Four Bash sessions still complete and
close in that baseline; successful sessions do not excuse the state loss. Its
configuration recovery is recorded before teardown and is not used as passing
qualification.

The original fetched-payload failure also had a fixture cause: the file downloads,
but `/tmp` was mounted noexec. An independent vendor-binary copy exits 126 there
while its original executes normally. The lab now restores ordinary executable
filesystem behavior and runs a hashed copied ELF before any module call. The
first added probe incorrectly renamed BusyBox, which selects applets from its
basename; those failures precede all owning calls. The corrected probe preserves
the basename. Exact failed inputs/captures remain separately sealed.

Early native starts also exposed non-executable `/run`, a missing FPM runtime
directory, a static-only readiness check, and the full-replacement settings API.
They were corrected or explicitly modeled before module qualification. Internal
networking and complete native snapshots remain mandatory.

Vendor autogenerated comments/headers may differ after a save; original
assignments remain intact. A conservative two-MB ambiguity boundary refuses a
snapshot rather than writing a possible tail. Older declared affected releases
remain unqualified: official 23.01.14 source lacks the current logs endpoint and
uses a different settings-array order. The original owner already sends the
newer order there. The fix refuses targets unable to expose a complete snapshot
before writing; it does not silently fall back to incomplete API rows. Other
architectures, releases, languages and custom installation paths need separate
validation.

Strict module RuboCop exits 1 and MSFtidy exits 2 before/after from the identical
existing duplicate-RPORT warning. No new offense is introduced. Existing Druid,
Superset RCE-owner and WordPress-admin exclusions remain unchanged. Published CI
is recorded separately for its exact commit. No PR was created.

## Suggestions

Use the serial command in [the lab guide](netalertx_execution/README.md). Keep
complete configuration/state comparisons and native file execution prerequisites;
do not infer a module error from an unvalidated payload environment.

Next, evaluate `auxiliary/scanner/http/pretalx_file_read_cve_2023_28459` using its
real application, conference, organizer authorization and schedule/ZIP export.
Current work is read-only source/guide review. No Pretalx image has been pulled,
target launched or module verdict assigned. Validate native export and patched
file-access controls before Framework collection, and retain short bounded tests.

Private immutable evidence:
`/Users/dwelch/.codex/reports/netalertx-execution-verified-20261112` has 354 manifest
entries and 70 distinct input files. Manifest SHA-256:
`a4d2a403955da8133f3301181e6537ce7376ecc6a0df0ea2461105d25bc61488`.
Every hash, read-only mode and single link count was independently verified.
Separate immutable bundles retain the original baseline, failed ELF probe and
source-regression comparison. Transient lab addresses/configuration captures
stay private.
