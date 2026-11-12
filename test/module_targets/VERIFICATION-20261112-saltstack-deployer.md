# Salt minion deployer investigation — 2026-11-12

## Summary

`exploit/linux/local/saltstack_salt_minion_deployer` remains **unqualified**.
The original diagnostic at `b2e78a965a037544d8bc3ab2debc6591c859631e`
ran four examples with two failures and no pending or outside-example errors.
The production module and existing shared Salt helper were unchanged.

## What looks good

The genuine source-pinned Salt 3000.1 master and two minions run in three
separate filesystems. Native controls established distinct mount namespaces,
per-daemon identity, 22 vendor source hashes and 15 package versions per host,
authenticated encrypted RPC, both/all and selected-minion copy/decode/execute,
exact bytes and executable modes. Before/after identities matched.

Ordinary public handlers supplied the exact generated x86 and x64 payload bytes.
Both ELF calibration cases opened real Meterpreter sessions on the selected
minion, with RPC-written proof files, native root PID checks and reporting
database records. The ordinary local module subsequently opened real owning
Meterpreter sessions on both minions from a master command shell. These owning
sessions passed the same per-host RPC, identity, peer, PID and SQL checks.

The first console was genuinely cold: the parent independently observed the
returned prompt, BOOT record and both freshly generated metadata snapshots.
Five bounded containers used an aggregate 1,408 MiB/1.7 CPUs/480 tasks. Compose
teardown succeeded; ten independent parent queries verified all five container
IDs, the network and project resources absent.

## Concerns

The normal shell-based owning run left its 336-byte encoded master upload and
both minions' 336-byte encoded files plus 250-byte ELF executables. These files
were captured before harness fallback deletion. The module did not satisfy
cleanup expectations after its job and sessions closed.

The master Python Meterpreter case reached the diagnostic's 60-second job-wait
limit with its owner job still running. It had no demonstrated owning callback;
the master upload and empty minion executable files remained. This case is
**inconclusive**, not proof of a module timeout or payload defect. A follow-up
diagnostic increases the job bound and compares legacy versus argv-based copy
through the same real master session.

The source's callback contains unresolved `cli` and `payload_name` references,
but neither the console nor Framework log recorded that exception in this run.
Its invocation path requires investigation before attributing the observed
cleanup failure to those references alone. The current `check` result establishes
only that a salt-master executable exists.

## Suggestions

Fix multi-minion and original-master cleanup in a separate source worktree,
verify callback integration, and repeat the actual owning paths. Then expand
selectors, repeated execution, both declared initial session types and feasible
payload/architecture paths. Other Salt versions and non-Linux targets remain
untested. Registration and native calibration alone do not qualify the module.

## Retained evidence

Original run: `tmp/module-target-tests/20261112T115258-1532b9`.
The read-only evidence snapshot contains 244 files and 107 pinned inputs;
every file was independently rehashed by the parent. Manifest SHA-256:
`fecb562c533fb06ed0edf8052eefabf26fa09d4d61fbeb075cbfaba5817da3a8`.
The private snapshot is named `saltstack-deployer-original-diagnostic-20261112`.

The earlier native-only pilot also passed and was torn down with eight parent
absence queries. Its six source digests were observed after completion; it did
not have a pre-runtime source map. The later Framework diagnostic pins its
actual inputs before startup. No human-authored module Scenarios were changed.

## Longer-bound diagnostic

Run `20261112T120308-ab8714` at
`e79e91ceefd37e095d4fe97a217d8e1775eb1a9f` again ran four examples with two
failures, no pending or outside-example errors, and passing native controls
before and after. The first console again passed the independent cold-cache
observation. The unmodified owner opened and proved two genuine minion sessions
through the master Python Meterpreter session. All three hosts retained its
files, confirming the cleanup defect on that initial transport as well.

A benign exact-copy control through that real master session returned after
15.145 seconds from the legacy API with only warning text, despite both files
being present. The maintained argv API with an explicit 120-second timeout
returned after 55.848 seconds with both Salt copy results; both native destination
hashes matched. Partial legacy output alone does not establish copy failure or
command completion. The final quick matrix omits this diagnostic comparison.

The first owning example failed during harness shutdown because its master
session PID remained. The following shell setup produced multiple handler
sessions and timed out before another owner invocation. These are separate
shutdown/setup failures, not evidence of another owning-module failure.
Stopping jobs before sessions is the working explanation for losing the
passive HTTPS listener before shutdown; the harness now closes sessions first. That correction still requires runtime
verification. Process birth identity and native socket closure checks have
also been added, without weakening the requirement for remote process removal.

Compose teardown and ten parent absence queries passed. The second read-only
snapshot contains 249 files and 107 pinned inputs, all independently rehashed.
Its manifest SHA-256 is
`4a5ba0651085215f806dfb4e414dcebe2abec521700c025fda6e609380cfb2ed`.
The private snapshot is named
`saltstack-deployer-longer-bound-diagnostic-20261112`.

## Resource-invalidated matrix attempt

Run `20261112T124207-e12acc` at
`a4ba14f42afce269ee5510c073a2b27d134775c7` is **invalid for module
qualification**. The first profile passed native controls and exact x64 ELF
calibration, but the master's cgroup recorded 11 OOM events and seven OOM kills
under its 256 MiB cap. The other four containers recorded no OOM or PID-limit
events; Framework's observed peak was about 391 MiB.

The agent deliberately interrupted the exact manager after observing those
counters. Its authoritative exit was 130; the observer controller exited 1 after
its waiting child was also interrupted. This was a resource-driven stop, not a
human interruption or a module-error verdict. All five containers and the
network were removed; ten independent parent absence queries passed.

The read-only snapshot contains 384 files and 111 pinned inputs, all independently
rehashed. Manifest SHA-256:
`a5a10a0c8afdb557b7d0ba74b4942035fcada65055e79198676682bf64742fb6`.
The private snapshot is named `saltstack-deployer-oom-fixture-20261112`.

The revised lab gives the master 384 MiB and Framework 640 MiB, preserving the
1,408 MiB/1.7 CPU/480-task aggregate and five-container maximum. Tests require
zero cgroup OOM and PID-limit events. Final native checks retain daemon/source
identity and fresh authenticated minion pings; they avoid duplicating the initial
copy/decode controls after two actual owning deployments.

## Resource-valid shutdown investigation

Run `20261112T125706-3e1cfd` at
`d716def3ce161a36a88364cd893872d6e724fbb6` recorded zero OOM and PID-limit
events. Native x64 calibration and the owning call through the master Python
session proved two minion callbacks. The module's files were absent on all three
hosts before harness fallback deletion. Its first profile nevertheless failed
two of three examples: the original master Python process remained alive after
shutdown, and the lifecycle guard prevented evaluating the following owning path.

The agent stopped the remaining matrix rather than repeat a known unhealthy
lifecycle. Manager exit 130 and observer exit 1 are agent-requested stops. Both
started projects passed ten independent parent absence queries each. Snapshot:
449 files, 113 pinned inputs, all independently rehashed. Manifest SHA-256:
`82bcff4e347a531316d3629950639dcb5c70b4985f40f26a5c9a1dd1ed308fa9`.
The private snapshot is named `saltstack-deployer-console-shutdown-20261112`.

The bulk console command temporarily sets a 15-second response timeout, but
passive `core.shutdown` explicitly waits ten seconds, so the console timeout is
not an established cause. The next harness uses the qualified gather workflow's
fresh RPC proof immediately followed by public `session.kill`, keeps handlers
live until termination, and closes dependent minion sessions before the master.
Remote PID birth identity, sockets and SQL closure remain mandatory; no native
force-kill fallback can satisfy qualification.
