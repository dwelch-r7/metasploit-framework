# Gogs hook qualification

The integrated checkpoint is **174 runtime modules, 108 qualified families and
1,369 functional cases**. All selected passing results retain current input
hashes, exact example counts, zero pending/outside errors and passing teardown.
Only `gogs_hooks` is newly qualified. The prepared rebase and fixed-rebase
profiles remain unrun and unqualified.

## Result and repair

The original hook module failed five of ten cases in
`20261110T145330-7cb9fb/gogs_hooks` (307.193 seconds). The repaired module passed
the same ten main assertions with unchanged effective options and deadlines in
`20261110T153132-316b7c/gogs_hooks` (303.302 seconds).

Requests now retain `TARGETURI` exactly once for login, CSRF, repository, hook,
file and cleanup operations. A branded HTTP 404 no longer passes the application
check. Non-session triggers wait for the existing bounded commit response before
cleanup deletes their repository. The original target log showed deletion
preceding a rejected push with a missing working directory. Session handlers
retain their asynchronous final trigger; unanswered or nonredirecting awaited
file creation now reports the failed operation.

The genuine targets are Gogs 0.12.3 at the root and 0.14.3 through `/gogs/`.
The complete independent gate passed 73 CLI operations, 327 HTTP operations and
22 proof records. Two native payload calibrations preceded module execution.
Four owning sessions were opened and used: two Bash and two Linux x64
Meterpreter sessions using the ordinary Bourne dropper. Repeated commands,
denied hook permission, rejected passwords, unrelated Apache and the missing
application path also pass. Twelve execution/restoration records are retained.

Earlier logging/schema/token and session-calibration failures remain preserved.
In particular, a registered Meterpreter row did not establish initialization,
and a Bash target exit did not automatically deregister its host session. Those
fixture failures are separate from the original five owning-case failures.

## Parent verification

The capture-backed focused corpus reproduces **22/10 before, 22/0 after**;
the parent independently passes all 22 examples against its Framework core
(2.868 seconds). Handler selections in these unit tests are mocks. Real payload
execution is established by the functional evidence above.

The parent verified all 60 qualified input hashes, all 134 files in the imported
invocation, and all 1,774 entries of the worker export. The export manifest SHA256
is `26a83290145e58470976916799f3e64dedce49f720ac95c042e63fec3737c527`,
under `/Users/dwelch/.codex/reports/gogs-hooks-module-validation-20261110-91efcbd29708/`.
Parent receipts are `tmp/gogs-hooks-parent-evidence-audit.json`,
`tmp/gogs-hooks-parent-source-receipt.json` and
`tmp/gogs-hooks-parent-checkpoint.json`.

All three new Ruby files lint cleanly. The owner retains the same four default
payload offenses and one duplicate RPORT offense; full msftidy exits 2 for those
inherited findings. Hook documentation retains one universal-option warning;
rebase documentation passes. Python AST and shell syntax pass. Both existing
human Scenarios sections are byte-identical (3,944 and 5,810 bytes).

## Resources and limits

The run used four containers with actual total limits of 1,600 MiB and 2.2 CPU.
Its fresh prompt, isolated BOOT and both atomic metadata snapshots were observed;
no between-invocation metadata seed was supplied. Exact teardown proves four
containers, one network and four volumes absent, with three empty project-label
queries and an empty global container inventory.

Scope is fresh module instances, the `master` default branch, Bash and Linux x64.
Windows, x86, other default branches, same-instance reset and rebase execution
remain unqualified. Shell cleanup explicitly sends target exit and proves PID
absence before closing the host session. Observer proof-file removal is separate
from module repository cleanup. Nonfatal vendor avatar-path warnings remain
preserved; no target configuration change was mixed into the owning repair.
The full campaign remains active and incomplete.
