# Salt minion deployment verification — 2026-11-12

## Summary

`exploit/linux/local/saltstack_salt_minion_deployer` is qualified for the scope
below: **12 examples, zero failures, pending cases or outside-example errors**.
The campaign reaches **213 qualified modules, 199 profiles and 2,080 functional
examples**. This does not establish every Salt version or Meterpreter transport.

The tested source is `530d3420f035519cbc7f581e677925a7710c8715`.
The owner SHA-256 is
`b46fb12c5c694ee702635cfac4b01e79d7f11315f66a4d4e910a511e25a551e3`.

| Profile | Owning payload | Examples / failures | RSpec duration |
|---|---|---|---|
| saltstack_deployer_3000_1 | linux/x64/meterpreter/reverse_tcp | 3 / 0 | 374.503 s |
| saltstack_deployer_x86_meterpreter | linux/x86/meterpreter/reverse_tcp | 3 / 0 | 390.112 s |
| saltstack_deployer_x64_shell | linux/x64/shell/reverse_tcp | 3 / 0 | 403.697 s |
| saltstack_deployer_x86_shell | linux/x86/shell/reverse_tcp | 3 / 0 | 365.701 s |

The first profile ran in `20261112T132115-5738eb`; the other three ran in
`20261112T132951-bd683e`. Each invocation began with an independently observed
cold console prompt, BOOT and two freshly generated metadata snapshots. Only
subsequent profiles in the second invocation used its own verified metadata seed.
All four profiles retain exact current input fingerprints: 112 each, 118 distinct.

## What looks good

Eight real owning calls opened twelve owning sessions across the four x86/x64
shell/Meterpreter payload combinations. Each payload was first calibrated with
an ordinary public handler's exact ELF bytes, native file hashes, ELF machine,
mode and real session RPC. Administrative setup established two master session
types: native Linux x64 Meterpreter and Unix command shell. The native master
ELF matches the documented initial-session family; the shell setup uses genuine
authenticated Salt RPC. These setup calls do not qualify unauthenticated access.

Each profile deploys to both minions with default `CALCULATE=true`, then performs
a second deployment selecting only minion A with calculation disabled. Native
before-controls independently prove all/selected Salt copy, decode and execution.
The master and two minions have genuinely separate filesystems. Each host's
22 vendor source hashes, 15 package versions, daemon birth identity, configuration
and unique role state remain stable. Fresh authenticated pings succeed afterward.

All 24 real sessions have RPC-written per-host proof, root/native PID birth
identity, peer/role attribution, actual database identity and closure records.
Fresh RPC immediately precedes public `session.kill`, with handlers still live
and dependent minions closed before their master. Verification records 24 PID
absence proofs, 216 socket absence snapshots and 24 closed SQL rows. All 24
owning-artifact snapshots are empty before harness fallback deletion.

The source fix scopes FileDropper registrations to each minion filesystem while
preserving the original master's registrations. It retains failed paths for
retry, preserves parent callbacks, guards deployment ownership and uses the
existing framed Salt helper to confirm copy completion before deleting the
master upload. The execution command, passive listener, options and declared
architectures/session types remain compatible.

A focused identical 17-case suite, seed `63127`, produced **15 failures on the
original source → zero on the fix**. These are multiple cases, not fifteen
separate bugs. The real Payload callback reproduced the original swallowed
`cli` NameError at debug level 1. FileDropper, counters and module replication
remain real; sessions, filesystems, transport, delivery and payload bytes are
unit doubles. The live matrix supplies genuine target coverage. Both source
versions passed strict module RuboCop and msftidy; final changed harness Ruby,
module docs, syntax and registration checks passed. Human Scenarios are unchanged.

## Concerns

Python HTTPS master execution and file cleanup were observed, but its remote
process remained alive after public shutdown in a separate diagnostic. That
transport is **unqualified**, with cause unverified. The bulk console timeout
is 15 seconds, while passive `core.shutdown` explicitly waits ten seconds;
that alone does not establish the cause. Native Linux Meterpreter and Unix shell
are the qualified initial transports. Other Meterpreter implementations,
non-root operation, complex/quoted paths, other operating systems and Salt
versions remain untested.

The module's existing `check` establishes only availability of a salt-master
executable; its `Vulnerable` label is not evidence of a vulnerability. This lab
uses legitimate administrative deployment. No full RSpec suite was requested or run.

Native controls alone did not reveal initial resource exhaustion. A stopped
attempt recorded seven master child OOM kills under a 256 MiB cap. The corrected
allocation gives the master 384 MiB, each minion 128 MiB, Framework 640 MiB and
PostgreSQL 128 MiB: the same **1,408 MiB/1.7 CPUs/480 tasks**, at most five
containers, one serial project. All 160 final cgroup OOM/PID-limit snapshots are
zero. Forty independent parent queries verify all twenty container IDs, four
networks and project resources absent. Docker is empty after completion.

## Suggestions

Investigate Python HTTPS process termination separately, retaining the successful
owning/file-cleanup observations without promoting that transport to qualified.
Expand current Salt releases and exceptional path/failure cases when a suitable
bounded lab is available. Keep native controls and resource counters independent
of module expectations when extending coverage.

## Retained evidence

The final read-only snapshot `saltstack-deployer-verified-20261112` contains both
complete final runs, 118 pinned inputs and static preflight evidence: **621
manifest entries**, all independently rehashed with read-only modes and single
links. Manifest SHA-256:
`ce0e4cae3d731c82b692c914a77ec7317b3a2007578d6c3d4bae5da43ac07770`.

The separately copied/rehashed unit seal has 100 entries plus its manifest;
all fourteen pinned unit inputs match the parent checkout. Its manifest SHA-256:
`0babd1d34ae1a6222ac216a440cfd6e63503b0309fcd83b641c3c06b30aa2a95`.
Worker commit `677d5b08cf30a2d6cbc99866ad913abf348e0989` was imported as
`10debebd680`. Unit spec SHA-256:
`4e47604986fc4d9b3a843dad196066b02fa8d4c69e2cff4052c860ff74e625bb`.

Earlier failures remain separately sealed; none was overwritten or counted as a
passing module result:

| Run | Disposition | Entries / inputs | Manifest SHA-256 |
|---|---|---|---|
| `20261112T115258-1532b9` | Original 4/2; genuine shell-owner leftovers; Python 60-second bound inconclusive | 244 / 107 | `fecb562c533fb06ed0edf8052eefabf26fa09d4d61fbeb075cbfaba5817da3a8` |
| `20261112T120308-ab8714` | Original 4/2; Python owning callbacks/leftovers proved; secondary harness shutdown/setup failures | 249 / 107 | `4a5ba0651085215f806dfb4e414dcebe2abec521700c025fda6e609380cfb2ed` |
| `20261112T124207-e12acc` | Fixed source, resource-invalidated; agent stopped after OOM evidence | 384 / 111 | `a5a10a0c8afdb557b7d0ba74b4942035fcada65055e79198676682bf64742fb6` |
| `20261112T125706-3e1cfd` | Fixed source, zero resource events; files clean, Python process closure failed; next owning path blocked by lifecycle guard | 449 / 113 | `82bcff4e347a531316d3629950639dcb5c70b4985f40f26a5c9a1dd1ed308fa9` |

Both stopped managers exited 130 following deliberate agent SIGINT requests;
their waiting observers were also stopped. These were not human interruptions.
Their respective ten and twenty parent absence queries passed. The earlier
native-only pilot passed with eight parent absence queries; its six source
digests were observed after completion, without a pre-runtime source map.
