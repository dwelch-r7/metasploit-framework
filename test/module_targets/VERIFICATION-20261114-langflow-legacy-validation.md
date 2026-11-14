# Langflow legacy unauthenticated validation — 2026-11-14

All **15 functional examples and 30 public module calls pass**, with four exact
command proofs and six complete session lifecycles. The campaign reaches
**239 modules qualified in covered paths, 288 profiles and 2,745 functional
examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_legacy_validation langflow_legacy_validation_protected
```

The [lab guide](langflow_legacy_validation/README.md),
[Compose recipe](langflow_legacy_validation/compose.yaml) and
[vendor record](langflow_legacy_validation/vendor.json) qualify
`exploit/multi/http/langflow_unauth_rce_cve_2026_0768` against the genuine official
Linux amd64 Langflow 1.4.2 image, pinned by digest. It contains Python 3.12.3,
langflow-base 0.4.2 and MCP 1.8.1; lfx is absent. Ten installed source hashes
cover validation, authentication, settings and startup. The backend runs as
UID 1000/GID 0. No application endpoint or implementation is replaced, and no
external AI provider is required.

| Genuine configuration | Cases / public calls | Commands / sessions |
| --- | ---: | ---: |
| Automatic login enabled | 8 / 16 | 4 / 6 |
| Automatic login disabled | 7 / 14 | 0 / 0 |

## Independent setup evidence

Offline inspection first establishes the actual legacy implementation:
`langflow/utils/validate.py` compiles each FunctionDef and calls `exec(code_obj)`.
Its API-key guard permits the default account without a supplied key when
automatic login is enabled. It explicitly describes a later authentication
behavior change; newer-version paths and settings are not assumed to apply.

Independent native requests verify the real version, benign validation,
invalid-Bearer-token rejection, exact repeated decorator/default-argument
effects and file ownership. Default unauthenticated execution works. With
automatic login disabled, anonymous validation returns 403 while a valid
fixture token still exercises the genuine execution path. Actual backend
settings are read through a separate canary. Complete flow responses remain
unchanged: 33 starter flows in the open profile and an empty protected registry.

The image's supported lazy-loading option exposes a vendor startup failure:
the starter-project updater dereferences a missing component template. The
bounded attempt never reaches a module call, has zero OOM counters, and is
preserved with six passing cleanup queries. Restoring the normal eager-loading
setting produces successful native calibrations in about 53 and 56 seconds.
The maintained recipes explicitly retain eager loading. This is a setup
finding, not an exploit-module failure.

Native held decorator callbacks separately block a concurrent version request
until released. Both authentication configurations then recover HTTP 200 and
normal backend health. These controls are independent of the Framework owner.

## Reproduced module defects and source corrections

The original public open-profile run executes two exact commands, then fails
the complete process-restoration check. A defunct child, PID 440/birth 7832296,
remains owned by backend PID 28 for the full bounded check. That profile stops
after two cases and four public calls; native before/after controls still pass.
The original protected profile runs seven cases and ten calls, with four
failures because HTTP 403 is reported as generic Failure::Unknown rather than
an authentication denial. Both projects pass sixteen independent teardown
queries. The original source is preserved before integration.

The corrected owner starts one daemon worker from a function default argument.
That worker runs the configured Python interpreter with an argument list,
passes the encoded payload unchanged, waits for and reaps the interpreter, and
uses DEVNULL streams. Payload globals, listener descriptors and fork behavior
remain outside the persistent backend. Random Python identifiers avoid reserved
words. The existing payload platform, architecture and public options remain.

Malformed version documents now return Unknown without exceptions. Only 1.4.2
receives the documented Appears result; other Langflow versions receive Detected
without an invented fixed-version claim. The
[CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/0xxx/CVE-2026-0768.json)
names 1.4.2 as affected and leaves other versions unknown; the
[original disclosure](https://www.zerodayinitiative.com/advisories/ZDI-26-034/)
identifies no fixed release. Version checking remains passive and does not
establish that a deployment permits unauthenticated validation.

HTTP 401/403 now produce NoAccess, absent responses and expected transport
failures produce Unreachable, and other non-200 responses produce UnexpectedReply.
The successful response contract remains. The shared acceptance helper can omit
unsupported credential options for this unauthenticated owner.

## Process-observation correction

The first fixed replay passes all eight open cases and six session lifecycles.
Its protected profile then catches a parent-zero, UID 1000 defunct process at
one immediate after-case snapshot, despite every module request returning 403.
The attempt is preserved separately rather than attributed to the module.

A separate network-disabled container runs no Langflow application or module.
Two named Docker exec helpers are identified by PID/birth and parent zero.
An observer records one helper transitioning **R → Z → absent**; both exact
identities disappear and both helper clients exit zero. Five independent
teardown queries pass. This reproduces the process-observation race independently.

The corrected tests require a clean initial baseline and use bounded polling
for exact process restoration before and after cases. Every observed snapshot
is retained separately from accepted, strictly restored snapshots. The audit
requires a later exact restoration for any discrepant observation and verifies
that its extra PID/birth identities disappeared. No retained PID, zombie or
callback allowance is added. The original backend-owned zombie would still
fail these checks.

## Final genuine verification

Run `20261114T083908-ca2858` completes in approximately **4 minutes 57 seconds**.
The original controller, manager and independent observer all exit zero.
The first actual cold BOOT, prompt and fresh metadata are observed independently;
the second console uses only the normal same-invocation seed, with matching
bytes. At this checkpoint, all **62 selected input hashes** match maintained
files, including the tested source and unit-spec bytes.

Every case repeats on the same selected owner without another `use`. The open
profile covers version checking, commands with AutoCheck on/off, Python command
shells, staged Meterpreter with both fork settings, refused ports and missing
paths. Every command appends exactly one marker and its file is removed.

All six sessions reach real ready events, perform remote identity/file
operations, produce exact UID 1000 bytes, match exploit/payload database
provenance, and close their database rows. All six live native health requests
succeed. Shutdown takes a fresh remote response, removes the exact PID/birth
identity, and restores the complete original process set without extra live or
defunct children, callback connections, Framework jobs or sessions.

The protected profile verifies passive version detection, denied commands with
AutoCheck on/off and absent marker files, denied shell and Meterpreter payloads
without sessions, refused ports and missing paths. All ten native probe
invocations exit zero. Complete before/after results and full flow responses
match. Accepted process states contain no zombies; the final replay needs no
discrepant-state retries.

Only three containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory, privileged
mode is disabled and published ports bind to localhost. OOM, OOM-kill and
PID-limit counters remain zero. All **sixteen independent teardown queries**
pass for exact resources, project labels and the global inventory. No
application volume is created. Five subsequent inventories are empty and the
shared heavy-lane lock is free.

## Checks, preserved evidence and limits

The focused source suite passes **17 examples**. The original bytes fail three
targeted regressions as expected. A real local generated-code probe repeats two
encoded payloads, verifies prompt validator return, separate interpreter/PID
identity, no backend builtin mutation or listener-descriptor inheritance, no
captured streams, and child reaping. HTTP and application context are explicit
doubles; the container replay supplies live application and payload evidence.

Strict Ruby lint, module/documentation tidy, syntax and diff checks pass. No
full RSpec suite is run. The human guide's `## Scenarios` through EOF remains
byte-identical, SHA-256
`70272f4be77a9acb95e4b5188576f1ab36a51c1128e5837eefbb5374427d49ec`.

Immutable local archives use independent copies, read-only permissions, no
hard links and reverified manifests:

| Evidence under `/Users/dwelch/.codex/reports/` | Files / selected inputs | Manifest SHA-256 |
| --- | ---: | --- |
| `langflow-0768-public-original-failure-20261114` | 247 / 61 | `89bcfa7043b5602beaa6de11815a7f3abbf47f3a916cd5acc5caea5021de4941` |
| `langflow-0768-helper-process-observation-20261114` | 270 / 62 | `2395e0834b3645c21328e0a0822bd79001c8e08ec002e2fb2d94c0de0adbdb08` |
| `langflow-0768-qualified-20261114` | 288 / 62 | `c1459d30b5cd9b831a6e8dbb9b910909b940baa5d923d29be61a16ca0927e22b` |

The final archive also includes offline installed-source captures, the preserved
lazy-startup failure, successful native calibrations, the independent helper
control and source-worker evidence. Qualified module source SHA-256:
`33ec1e199977ec544f8afc873848352aece1074e513cfbb46152dbe37f5addf7`.
Inventory now has 5,179 source files, 241 registered owners, 264 pending
documented container reviews and zero stale reviews. Previous Druid,
FreeSWITCH, Superset and WordPress deferrals remain open. The older remote
Mettle `post/test/file` timeout still has cause unverified.

## Self-review

- **Summary:** Independent target calibration and repeated public execution
  qualify the covered legacy unauthenticated and protected-target paths.
- **What looks good:** Setup failures, source defects and an observer race have
  separate evidence; process, descriptor, callback, database and registry
  invariants remain strict.
- **Concerns:** Scope is the pinned one-worker Linux 1.4.2 image and exercised
  Python payloads. Other versions, platforms, URL prefixes, TLS and identity
  providers remain unqualified. Passive version detection does not prove access.
- **Suggestions:** Continue the remaining documented candidates and retain the
  failed attempts; do not generalize this result into a broader affected range.
