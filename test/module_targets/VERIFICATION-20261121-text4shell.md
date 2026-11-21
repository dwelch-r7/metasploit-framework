# Commons Text checks and exact command delivery

Date: 2026-11-21. Three serial native-gated profiles pass **15/0/0**, including
four proven owning command executions. This qualifies the Unix Command target
and the stated check/error paths, not the default Java target or all module paths.
The full valuable-module inventory goal remains active.

## Target and reproduction

Use the [maintained recipe](text4shell/README.md) for the exact guarded command,
pinned source archive, build/runtime image digests and the explicit POST
derivative. The original referenced Spring application calls the real
`StringSubstitutor` interpolator. Java is **1.8.0_412**, with **Oracle Nashorn**.
Commons Text is independently identified as 1.8 or 1.10.0 from the loaded class.
The original GET controller and the POST derivative's active source hashes are
checked. Only the POST mapping annotation changes in that derivative.

Each profile runs one UID1000 application container capped at **384 MiB / 0.7
CPU**, with a dynamically assigned loopback port, bounded temporary files and no
privileged mode, Docker socket or persistent volume. The shared guard/namespace
serializes the profiles and verifies teardown before continuing.

| Profile | Examples/failures/pending | RSpec seconds | Proven owning command executions |
| --- | --- | ---: | ---: |
| Original GET, Commons Text 1.8 | 5/0/0 | 87.57 | 2 |
| Explicit POST derivative, Commons Text 1.8 | 5/0/0 | 62.74 | 2 |
| Original GET, Commons Text 1.10.0 | 5/0/0 | 47.03 | 0; both owning requests remain ineffective |

These durations include fresh Framework console startup and native readiness.
No clock, random delay, HTTP response, module or payload implementation is stubbed.

## Independent native gates and owner proof

Before any owning verdict, the exact plain and rich commands must execute via
direct shell and direct Nashorn `ProcessBuilder`. The rich bytes include both
quote types, dollar/backtick characters, a backslash, ampersand, Unicode and
physical CR/LF. The same commands then reach the genuine CLI interpolator and
HTTP application. Both execute on 1.8 and create no proof on 1.10.0. Files are
read independently for exact bytes and UID1000, then removed. A foreign file,
application JAR, controller and POM preserve exactly.

The actual module performs two checks on one selected module, then both command
bodies on one selection. Traces verify original exploit/execute_command calls,
exact command bytes and GET-query versus POST-form placement. Physical owner
proof equals the independent native proof. Fourteen actual checks cover positive
and fixed results, an unconsumed parameter, the original application's 405 POST
response and refused connections. Refused exploitation raises Unreachable.
Session/job registries remain empty throughout these command-only profiles.

The module lacks AutoCheck. Tests retain that behavior: the fixed-library owner
can accept HTTP 200 while executing no command; no automatic refusal is claimed.
The two fixed calls are not counted as successful execution.

## Retained failures and repair

The first three-profile frame is retained separately:

- GET had 5/0/0 but the runner correctly invalidated its snapshot after a README
  was added during the run. It is not counted as qualified evidence.
- POST had 5/1/0 after real native readiness and both actual command proofs.
  Both initial checks raised `NameError: uninitialized constant Rex::Stopwatch`.
  Later payload loading incidentally supplied the constant, exposing a load-order
  dependency rather than a missing vulnerable target.
- Fixed had 5/1/4 with no owning calls. Its native oracle incorrectly required
  disabled interpolation to raise; actual 1.10.0 returned the original lookup
  literally. This was a harness assumption, not a module failure or readiness pass.

The source repair was made in a separate worktree and committed as
`842d2d724e3`: add the direct `require 'rex/stopwatch'`, matching existing HTTP
modules. No targets, payloads, timing logic or automatic checking behavior change.
Final module SHA256 is
`f19e1259785df35a5c20a63f534504d31138f0adb450f94e3109951b70c8b235`.

The frozen replay follows actual fixed-library literal preservation and still
requires positive shell/Nashorn proof plus no interpolator/HTTP execution. POST
and fixed consoles start with Stopwatch undefined; selecting the repaired module
loads it, and both checks pass. All three final input snapshots remain unchanged.

## Checks, cleanup and remaining scope

Ruby lint, source syntax and module tidy introduce no new offenses. One inherited
missing-AutoCheck informational offense remains. Module-doc tidy retains the
same inherited universal TARGETURI warning as the original document, verified
against the untouched document in the separate worktree. Python AST, manifest
paths and whitespace checks pass. The **8,087-byte** human Scenarios tail is
unchanged. Twelve before/after memory/PID cgroup captures contain only zeros.

The current fully passing set reaches **132 cases / 37 profiles**, with **47**
retained used/closed sessions from earlier qualification and **411** current
declared input hashes. These command profiles add no sessions. All **15 new /
709 recorded Docker objects** are independently absent; both Docker contexts are
globally empty, including stopped containers. No prune or daemon restart is used.

Default Java in-memory delivery, native/owner Java sessions, Linux dropper,
Windows targets, other library/runtime combinations and further input paths
remain unqualified. A separate ProjectSend registration repair has matching
unit evidence but still awaits parent native replay and is not integrated here.
Raw initial/final frames, source hashes, controls and cleanup receipts are sealed
in the local evidence capsule referenced by the continuation checkpoint. No PR.
