# n8n default wget/Meterpreter sessions

The new [session profile](n8n_expression_sessions/README.md) passes **2/0/0**,
using and closing one independent stock-payload session and two actual owning
sessions on one module selection. Replaying both existing expression profiles
against the repaired source gives **10 examples / 0 failures / 0 pending**.
A confirmed live-session API stall is repaired in isolated commit `6bd764b8f554`
and integrated as `abc78801a54`. No PR is created; the full inventory goal remains active.

## Confirmed fault and native control

The original default target opens a wget-delivered inline Linux x64 Meterpreter
session. However, n8n then stops answering API requests while that session lives.
The first maintained run records **2 examples / 1 failure**: the independent
stock session works and closes, but the owner fails the live workflow-registry
check with an HTTP timeout. A separate settings request also times out. The
owner session is closed during fixture recovery; queued cleanup requests then
complete and final workflow/execution tables are empty. This is not evidence
of permanent workflow leftovers, nor is merely opening that session counted
as a qualified owning run.

An independent workflow on the same unmodified n8n 1.120.0 image starts a
harmless, UID-1000 background Node child. With the original `execSync` capture,
the child's stdout remains a socket, settings times out after 1.016 seconds,
and execution finishes only after exact PID/command-line-verified termination.
With ignored I/O, the child has `/dev/null` stdout, settings returns 200 in
0.024 seconds while it lives, and the workflow completes successfully before
termination. Both controls request exact-PID child termination, remove their proof files
and workflows, and verify container teardown; installed vendor hashes stay unchanged. No owning Metasploit method is invoked in this control.

This matches the documented synchronous blocking and captured-I/O behavior in
[Node 22.21.0](https://nodejs.org/download/release/v22.21.0/docs/api/child_process.html#child_processexecsynccommand-options).
The small repair keeps synchronous execution, ignores unused child I/O and
returns an explicit empty string because ignored output cannot be converted
with `.toString()`. Payload defaults and the existing command bad-character
contract are unchanged. No payload command is rewritten or backgrounded by the test.

## Maintained replay

| Profile | Examples / failures / pending | Seconds | Evidence |
| --- | --- | --- | --- |
| [n8n_expression](n8n_expression/README.md) | 5/0/0 | 63.48 | Native controls, actual check, bad password, refused port, repeated command proof |
| [n8n_expression_fixed](n8n_expression_fixed/README.md) | 3/0/0 | 28.35 | Native fixed-release denial, actual Safe, repeated AutoCheck refusal |
| [n8n_expression_sessions](n8n_expression_sessions/README.md) | 2/0/0 | 83.97 | Native stock session, default owning session, same-selection repeat |

The session recipe uses the existing pinned official 1.120.0 amd64 image,
Node 22.21.0 and UID 1000, plus a small PostgreSQL Framework reporting service.
The host console runs outside Docker; the victim receives only a read-only
Node evidence helper. Native owner setup/login, ordinary IIFE and unsafe file
expression controls precede callback and stock-payload calibration. Real issued
cookies are reused by fixture observers; the normal login limiter stays enabled.

The native handler's already-generated wget command reaches native Node
`execSync` unchanged. The actual owner first selects normal target/payload
defaults with AutoCheck, then repeats with AutoCheck disabled. Callback and
fetch addresses/ports and a tracked `/tmp` destination are fixture options;
the default wget command, inline payload and `FETCH_DELETE=false` remain intact.

Passive traces retain actual source paths, request/response and command bytes.
The served x64 ELF must match the physical fetched file byte-for-byte. Each
session writes an exact remote proof, has independently observed UID/PID/birth
and owning socket, and keeps n8n responsive. The module removes its own workflow
while the session is live; two complete foreign records and global SQLite IDs
remain unchanged. A fresh RPC precedes graceful shutdown, the original SQL row
closes, the payload PID disappears and process/listener/job/session baselines return.
The default retained executable is recorded before deliberate fixture removal.
Final native teardown requires zero workflow, execution and execution-data rows
and unchanged installed vendor hashes.

## Checks, preservation and scope

Three new Ruby files pass RuboCop; Node syntax, Compose, default acceptance
exclusion, module documentation tidy and direct metadata tidy pass. The existing
twelve module unit cases pass before/after the isolated fix; seven support
formatter cases are excluded from that count. Integrated source bytes match the
tested isolated source. The complete existing human Scenarios section remains
byte-for-byte unchanged.

Standard module RuboCop/msftidy still report exactly four existing offenses:
two redundant top-level platform/architecture declarations and two default-payload
declarations. Exact cop/message/source comparisons are identical before/after.
Those metadata defaults are preserved; these checks are not reported as clean.

The current set has **72 cases across 22 profiles**, **28 used/closed sessions**,
**250 current declared inputs** and **132 zero cgroup captures**. The other
nineteen profiles retain 62 cases with unchanged inputs. Historical coverage is
324 owners in stated paths, 692 profiles and 4,847 cases; these totals describe
covered paths, not complete qualification of all modules.

Serial profiles use at most two capped containers. All **14 new / 508 recorded
Docker objects** independently verify absent, including two unused tool helpers
created by worker initialization and removed immediately. Global running/stopped
containers and owned ephemeral networks/volumes are empty. Original failed
inputs, the image-native diagnosis and successful replay are retained separately.

Windows, other payload families/releases, member roles, MFA, external databases
and long-lived foreground commands remain unqualified. The fix retains synchronous
execution rather than promising asynchronous execution for arbitrary commands.
These opt-in Docker tests do not run in ordinary unit CI. CI status must be
assessed for the exact published head; an unrelated green workflow is not their proof.

## Self-review

| Area | Assessment |
| --- | --- |
| Summary | One confirmed lifecycle fault repaired; default Linux fetch sessions gain reproducible coverage. |
| What looks good | Independent native attribution, unchanged payload defaults, real repeated sessions and complete workflow/process/SQL cleanup evidence. |
| Concerns | Four unchanged lint offenses and the explicit untested paths above remain. |
| Suggestions | Continue the broad inventory; qualify additional feasible owner paths without expanding these results into whole-module claims. |
