# Redis replication execution and state recovery

The [bundled-extension profile](redis_replication/README.md) passes **two examples,
zero failures/pending/outside errors** against genuine Redis 5.0.14 x64/glibc.
The original module opens a working session but leaves its persistence filename,
loaded extension and transferred file behind. With the owning source as the sole
changed declared input, the frozen native comparison changes **2/1 to 2/0**.
The repaired module executes twice and restores the selected state after each run.

## Native prerequisites and failure separation

The official image is pinned by digest and runs Redis as UID 999. Native
`redis-cli` checks the actual server, configuration and initially empty module
list before loading the original bundled `exp.so`. Two commands write exact
quoted Unicode/CRLF bytes; independent file reads and ownership checks verify
their effects. The native extension is then exercised with a stock handler and
the documented staged `linux/x64/meterpreter/reverse_tcp` payload. This genuine
foreground extension call remains live while its session is used and closed;
its measured reply duration includes that session lifecycle and is not isolated
payload startup latency. Native unload, file removal and baseline equality gate
the owning tests.

The owning check must identify Redis 5.0.14. Each subsequent owning execution
must open the expected Meterpreter family, prove UID/PID/kernel birth and exact
file bytes through public session APIs and independent target observations,
answer a fresh public request, shut down and disappear physically. Framework
session registrations and jobs must also be empty. The two final owning runs
have no error diagnostics. A failed selected-state comparison prevents the next
attempt; the harness retains observed state rather than repairing it.

Earlier attempts remain separate:

- An oversized single-payload pilot was stopped deliberately during its inline
  transfer. Its native control passed, but owning completion is unqualified.
- One nonexistent dependency path failed before process/container launch and was
  corrected. It supplies no module verdict.
- A broad error-output matcher initially rejected a real callback before using
  it. The original foreground `shell.exec` waits for its process and can exceed
  the module read timeout. The revised matcher permits only that specific
  captured diagnostic, still requires physical session proof and rejects cleanup
  errors. Unproved callbacks are excluded from used/closed counts.
- The valid original run and the final lint-clean frozen original both prove a
  working owning session, followed by the same three selected-state differences.
  This is an operational cleanup defect, not failure to obtain execution.
- An initial cleanup candidate removes the file but blocks on module unload and
  replication reads while the foreground session lives. The strict harness
  rejects those errors. State recovers only after that unproved owning callback
  is closed; this candidate is not qualified.

## Repairs and regression coverage

The module captures the original persistence filename/directory and replication
endpoint before mutation and verifies state-changing acknowledgments. It
registers the absolute transferred path with FileDropper before a session can
arrive, restores the filename before triggering and unloads only an extension
whose load was positively acknowledged. Cleanup preserves independently changed
filename/upstream values. Retained cleanup is bound to the configured host/port,
so changing targets cannot apply a previous target's ownership to another peer.
A fresh cleanup connection prevents a late foreground reply from acknowledging
the next command.

The existing Linux payload forking option is enabled by default. The complete
shell command group redirects stdin/stdout/stderr while remaining synchronous,
preserving upload order and explicit per-command file redirections. Together
these changes let Redis resume before cleanup instead of waiting for the live
payload or an inherited output pipe. No shared payload library, extension
template, timeout or target is changed.

The retained cleanup unit file has **37 examples**, including seven shared
framework examples: the original has 23 failures; an early candidate has four
endpoint-ownership failures; the corrected cleanup source has zero. The final
fork/stdio regression file has **42 examples**, with five failures on that
cleanup-only source and zero after the follow-up. It includes real x86/x64 raw
and ELF payload generation and a real host shell check of ordered writes and
stdio closure. Parent integration passes **42/0**. These generation checks do
not qualify native x86 execution or the dynamically compiled target path.

Syntax passes. The new spec and acceptance helpers are RuboCop-clean. The owner
retains exactly two inherited offenses, hardcoded default PAYLOAD and missing
AutoCheck, with zero new offenses. Same-HEAD baseline/candidate module tidy
both exit 2 for these inherited findings. Module-document tidy passes and the
existing human Scenarios remain byte-identical.

## Evidence, resources and limits

Authoritative original runtime: `20261122T074516-b7cd44`. Rejected cleanup runtime:
`20261122T080217-2882f1`. Final runtime: `20261122T081259-5a41eb`. Frozen input
hashes, actual native commands, public session observations, failed attempts and
both source-agent evidence capsules are retained. Only the production owner
differs between the authoritative original and final functional input sets.

Across the retained attempts, **ten actual sessions are used and closed**:
seven native controls/earlier proven owning sessions and three final sessions.
Unproved callback notifications are excluded. Adding this profile brings the
retained set to **330 cases / 73 profiles / 739 current inputs**, with
**311 ordinary used/closed sessions** and 21 separate source variants. All
728 previous declared inputs remain byte-identical.

One capped target/Framework pair runs at a time and is removed immediately after
each phase, including its network and anonymous volume. Two initialization
helpers are removed by exact ID. Both Docker contexts finish globally empty,
including stopped containers, and all **28 new / 1,139 recorded resource
identifiers** are absent. No new global volume remains. No image/cache pruning
or daemon restart occurs. The earlier unrecorded Erlang pilot volume ID remains
excluded from exact-ID counts with its prior set-based absence proof retained.
The user's one-time broader container cleanup check also finds both contexts
empty; ordinary cleanup retains its task ownership scope.

State equality covers six selected CONFIG values, raw module list, selected
replication role/master fields and the `/data` entry set on an initially empty
master. It does not establish preservation of existing database contents,
overwritten files, full process ancestry or server identity across restarts/DNS
changes. Authentication, native replica targets, other releases, x86 execution,
explicit forking overrides and `CUSTOM=true` remain unqualified. A genuine
Alpine Redis metadata probe is retained for the compiler/ABI investigation;
metadata alone supplies no dynamic extension execution verdict.

The complete valuable feasible-module goal remains active. No PR is created.

**Summary:** Repairs native-proven cleanup and foreground payload blocking.
**What looks good:** Independent controls, frozen comparisons and two owning repeats.
**Concerns:** Compiled-extension and wider target/data-preservation paths remain open.
**Suggestions:** Qualify genuine compiler/ABI/raw-buffer prerequisites next.
