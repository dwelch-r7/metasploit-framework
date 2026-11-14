# Langflow saved-flow execution — 2026-11-14

All **20 functional examples and 40 public module calls pass**, with eight exact
command proofs and twelve complete session lifecycles. The campaign reaches
**236 modules qualified in covered paths, 281 profiles and 2,686 functional
examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_flow langflow_flow_enabled
```

| Genuine configuration | Cases / public calls | Commands / sessions |
| --- | ---: | ---: |
| Custom components disabled | 10 / 20 | 4 / 6 |
| Custom components enabled | 10 / 20 | 4 / 6 |

The [lab guide](langflow_flow/README.md), [Compose fixture](langflow_flow/compose.yaml)
and [vendor record](langflow_flow/vendor.json) pin the official Linux amd64
Langflow 1.10.0 image by digest. Installed packages are langflow-base 0.10.0,
lfx 1.10.0, MCP 1.27.2 and Python 3.14.5, running as UID 1000/GID 0. Native
controls verify six installed endpoint, settings, loader and flow-guard source
hashes. No application source patch or external AI provider is used.

## Independent controls and scope

A benign component blueprint is captured from the enabled backend rather than
invented from the owning exploit. Its flow produces a valid Data output. On
the protected backend, direct custom component creation returns 403, and a
normally typed custom flow is saved but its build returns 400 with the actual
policy rejection. The equivalent empty `data.type` flow builds successfully
and executes an exact native canary once. Its file is absent after saving and
present only after building. Repeated independent canaries produce the same
result; each created flow and controlled file is deleted.

This qualifies the empty-node-type guard bypass implemented by
`exploit/multi/http/langflow_auth_rce_cve_2026_19295` on this pinned image.
The [IBM advisory](https://www.ibm.com/support/pages/node/7284733) describes a
crafted template-type/ForwardRef wrapper-flow path. That separate mechanism,
its CVE attribution to this implementation, other target versions and the
fixed-release behavior remain investigation limits. The passive version check
uses the advisory range and returns `Appears`; it does not establish execution.

## Confirmed source defects and fixes

The original public invocation executes one exact command and deletes its
flow, but leaves an exited child in the persistent Langflow worker. The
original run stops after four cases and seven public calls with one failure.
Native controls before and after still match, including the backend PID,
159 builtin keys and empty flow registry. The retained process snapshot shows
the added child in state `Z`. This is a verified source lifecycle defect.

The owner now starts a daemon thread that waits for a separate Python payload
process with `subprocess.run`. Long-lived payloads can remain active while the
flow finishes, and exited payload processes are reaped. The component-local
guard matches the observed saved-flow compilation boundary; no backend builtin
ledger is introduced.

The actual build endpoint normally returns a queued job ID immediately. The
owner requests direct delivery and requires a valid component result followed
by the final `end` event before attempting flow deletion. Its status message
reports build completion without claiming payload execution. A per-attempt
ledger retains each flow ID, bearer token and HTTP origin. Failed deletion can
be retried; changed targets receive no old token; parent cleanup always runs.

Review also reproduces a malformed version raising `ArgumentError` from
`check`. A narrow rescue now returns reason-bearing `Unknown`. Synthetic API
cases cover malformed text and versions 0.9.9, 1.0.0, 1.11.1 and 1.11.2. These
cases prove the classification contract, not exploitability on those versions.

## Genuine execution and cleanup

Run `20261114T052327-67dc36` completes in approximately **6 minutes 53 seconds**,
including a fresh cold console, two serial deployments, controls and teardown.
The original controller, manager and independent observer all exit zero. The
first actual BOOT, prompt and fresh metadata are independently observed. The
second console uses only the normal same-invocation seed, with matching bytes.

Both profiles repeat version checks, incorrect credentials with AutoCheck
on/off, exact commands with AutoCheck on/off, a Python command shell, staged
Python Meterpreter with forking enabled and disabled, a refused port and a
missing application path. Every case repeats without another `use`.

Each command appends exactly one marker. All twelve sessions reach the real
ready event, perform remote identity/file operations, create exact UID 1000
file bytes, match exploit/payload database provenance and close their database
rows. A genuine version request succeeds while each session is open. Shutdown
requires the exact remote PID/birth identity to disappear. The entire original
backend process set returns, without a live or defunct extra child, callback
connection, Framework job or session.

All **88 native invocations** exit zero, including twelve live-session health
requests and **72 authenticated registry checks**. All four before/after full
controls pass; each backend's PID, complete 159-key builtin namespace, native
proofs and flow IDs match. Native canaries inspect the backend namespace through
actual flow execution; a standalone Python process cannot prove that property.

The limiter remains enabled with the supported login allowance of 100/minute.
Controls verify the effective settings and six consecutive valid logins beyond
the default allowance. The full burst is not qualified at the production default.

At most three containers run: target 3,072 MiB/one CPU, Framework 768 MiB/one CPU,
and PostgreSQL 128 MiB/0.2 CPU. Swap equals memory, privileged mode is disabled,
and published ports bind to localhost. OOM, OOM-kill and PID-limit counters stay
zero. All **16 independent teardown queries** pass for six exact container IDs,
two networks, project labels and global inventories. Five subsequent inventories
are empty, and the shared lock is free. No application volume is created.

## Validation and preserved evidence

Focused source verification passes **25 examples: 18 owner cases and seven
loaded support examples**. The first identical-spec comparison produces ten
failures before the lifecycle fix and zero afterward. The later five-case
version comparison produces one malformed-version failure before its fix;
the final complete focused file passes. Actual emitted Python is exercised
twice with a held loopback connection, separate PID, transport EOF and child
reaping. HTTP, payload, Component, Output and Data are explicit doubles; the
container replay supplies genuine application and payload session evidence.

Strict Ruby lint, module tidy, documentation tidy, Ruby/Python syntax and input
path checks pass. Filtered discovery passes seven shared examples without lab
environment or load errors. No full RSpec suite is run. The original human
`## Scenarios` through EOF remains byte-for-byte unchanged, SHA-256
`d356dd5f7533f5431b0a029d12015c18b8417d64aa69ff72c866f1ed7d2b4633`.

The first native build probe wrongly expects completed output in the initial
200 response. It actually receives a queued job ID. That oracle failure is
sealed before the client is corrected to consume job events. It calls no owner.
The protected control is then separately calibrated and passes.

The original public zombie failure is preserved in
`/Users/dwelch/.codex/reports/langflow-flow-public-zombie-failure-20261114`:
164 files, 59 selected inputs, manifest
`d31f4e2be81ccc27cfc02438785a24a34ef8357adce89068d7a17ea512ad8a0a`.
Its original controller exits one, observer exits zero, and eight independent
cleanup queries pass before any selected inputs change.

The final immutable archive is
`/Users/dwelch/.codex/reports/langflow-flow-qualified-20261114`:
**304 files and 62 selected inputs**, copied without hardlinks and independently
hash-verified. Its `MANIFEST.sha256` hash is
`7490fe81e426d70caa979e961742f1752d9826e42ce51028cddeb7518e84cf8d`.
Source commits are `69912efabdd` and `212be064599`; the fixture commit is
`3da38234764`. Final owner SHA-256 is
`f405e24640cc321da880433d915ffbe0eaaa10f8af704e731e5d5223f48c53ef`.
All tested inputs remain identical after sealing.

## Self-review and remaining scope

**Summary:** Saved-flow execution, both policy branches, repeat runs, command
and session lifecycles, build completion and cleanup are verified.

**What looks good:** Independent controls distinguish policy enforcement from
the bypass; exact process, flow, database and namespace evidence rejects
false success. Scenarios and public module options are preserved.

**Concerns:** No material finding remains in the tested scope. Qualification
covers one official image and one backend worker. Other versions, replicas,
payload families and the advisory's separate wrapper path remain untested.
The older remote Mettle `post/test/file` timeout remains cause-unverified.

**Suggestions:** Investigate CVE attribution and fixed versions separately,
then continue the container-feasible queue. The inventory records 5,179 source
files, 238 registered owners, 267 unreviewed documented container hints and
zero stale reviews. Standing deferrals remain `druid_js`, `freeswitch_batch`,
`superset_rce_owner` and `wordpress_admin`; no new owner is deferred here.
