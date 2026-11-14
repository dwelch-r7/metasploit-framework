# Langflow command validation — 2026-11-14

All **27 functional examples and 54 public module calls pass**, including
**18 exact command proofs and 12 complete session lifecycles**. The campaign
reaches **238 modules qualified in covered paths, 286 profiles and 2,730
functional examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_validate langflow_validate_auth langflow_validate_newer
```

The [lab guide](langflow_validate/README.md), [Compose fixture](langflow_validate/compose.yaml)
and [vendor record](langflow_validate/vendor.json) exercise
`exploit/multi/http/langflow_rce_cve_2026_0770` against genuine official images,
pinned by Linux amd64 digest. No HTTP endpoint or application implementation is
replaced, and no AI provider is required.

| Genuine configuration | Cases / calls | Commands / sessions |
| --- | ---: | ---: |
| Langflow 1.7.3, automatic login enabled | 11 / 22 | 10 / 6 |
| Langflow 1.7.3, automatic login disabled | 11 / 22 | 4 / 6 |
| Langflow 1.8.4, automatic login enabled | 5 / 10 | 4 / 0 |

Both images run as UID 1000/GID 0 with Python 3.12.12. The 1.7.3 image contains
langflow-base 0.7.3, lfx 0.2.2 and MCP 1.25.0; 1.8.4 contains langflow-base
0.8.4, lfx 0.3.4 and MCP 1.26.0. Seven installed validation, authentication,
constants and settings source hashes are checked for each version.

## Independent controls and corrected assumptions

Native requests establish genuine version responses, anonymous validation
denial, incorrect-password denial, valid explicit login, the effective automatic
login policy and benign validation. Independent shell canaries append exact
bytes once per request, repeat and remove their UID 1000 files. Held loopback
callbacks separately demonstrate that synchronous validation blocks a concurrent
version request on both releases; closing the callback restores HTTP 200 and
normal health.

The native setup exposed three harness assumptions before module acceptance:
a missing child-probe environment, automatic login forcing the built-in
`langflow` credentials, and disabled automatic login returning 400 on 1.7.3
rather than the newer fixture's 403. Each failed attempt is preserved and its
six independent teardown queries pass. These are setup observations, not module
failures.

The maintained profiles use the supported `LANGFLOW_LAZY_LOAD_COMPONENTS=true`
setting. A separate canary reads its actual value inside the backend, rather
than inferring it from an environment variable. Validation still loads and
executes its genuine implementation. Complete native before/after results match.
The maintained flow registries are empty; their complete responses also match
across all public calls. Populated-flow preservation is not claimed here.

## Confirmed source defects and corrections

The original module executes `subprocess.run(..., shell=True,
capture_output=True)` synchronously on the HTTP worker. The corrected-startup
1.7.3 public reproduction runs 11 cases and 19 module calls: four exact commands
pass, then three genuine sessions reach ready events and remote operations but
all three live backend health requests time out. There are three case failures,
no errors outside examples, unchanged native before/after controls and eight
passing independent teardown queries.

The corrected owner starts a daemon thread whose target waits for and reaps a
separate shell process. All three standard streams use DEVNULL, so persistent
payloads do not retain captured pipes. Compound command syntax, generic
`ARCH_CMD` compatibility, explicit-login/automatic-login fallback and the
payload's Meterpreter fork setting remain supported. Invalid or blank token and
version documents are handled without dereferencing incompatible JSON shapes.
The inherited RPORT default stays 7860 without duplicate registration.

The original owner also labels every version above 1.7.3 safe. Genuine 1.8.4
native canaries execute successfully. Its original public boundary run has
five cases, eight calls and two failures: the incorrect safe result and the
resulting AutoCheck rejection. Disabling AutoCheck produces two exact commands.
The corrected owner returns reason-bearing `Detected` beyond the documented
affected range; AutoCheck permits that result with a warning.

The [vendor disclosure](https://www.zerodayinitiative.com/advisories/ZDI-26-036/)
and [reviewed advisory](https://github.com/advisories/GHSA-g22f-v6f7-2hrh) identify
no patched release. The 1.8.4 result establishes this implemented path on the
pinned image; it does not establish an affected range for every later release.

## Genuine final verification

Run `20261114T073455-947e29` completes in approximately **10 minutes 16 seconds**.
The original controller, manager and independent observer all exit zero.
The observer verifies the first actual cold BOOT, prompt and fresh metadata.
Later consoles use only the normal same-invocation metadata seed, with matching
bytes. All **65 selected input hashes** still match the maintained files.

Every case repeats without another `use`. Coverage includes explicit, cleared
and incorrect credentials with automatic fallback where enabled, AutoCheck
on/off, exact commands, adapted Python command shells, staged Python
Meterpreter with forking enabled and disabled, refused ports and missing paths.
The 1.8.4 profile covers passive classification and commands; its session paths
remain unqualified by this checkpoint.

Each command appends exactly one marker and its file is removed. Every session
reaches the real ready event, performs remote identity and file operations,
produces exact UID 1000 bytes, matches exploit/payload database provenance and
closes its database row. All twelve live native health requests succeed. Each
shutdown takes a fresh remote response and requires the exact PID/birth identity
to disappear. The complete original process set returns without an extra live
or defunct child, callback connection, Framework job or session.

All 18 native probe invocations exit zero. Three capped containers run at a
time: target 3,072 MiB/one CPU, Framework 768 MiB/one CPU and database
128 MiB/0.2 CPU. Swap equals memory, privileged mode is disabled and published
ports bind to localhost. OOM, OOM-kill and PID-limit counters remain zero.
All **24 independent teardown queries** pass for exact container/network IDs,
project labels and the global inventory. No application volume is created.
Five further inventories are empty and the shared heavy-lane lock is free.

The original 1.7.3 console setup first hit the runner's fixed 120-second health
wait before any owner call; native starts took roughly 140 seconds. An optional
integer `health_timeout` from 1 to 600 seconds now supports measured startup
requirements. These two profiles use 240 seconds; all other defaults remain
120. Compose continues immediately when healthy, and functional-test deadlines
remain separate. The failed first deployment and manual cold observation of
its successful 1.8.4 successor are preserved.

## Local checks, evidence and remaining scope

The focused source spec passes **24 examples**, including two real local held
compound commands, nonblocking validator return, absent captured streams and
reaped shell processes. The original owner fails two targeted regressions as
expected. HTTP and application context are explicit doubles in those tests;
the container replay supplies the real application and payload evidence.

Focused runner checks pass **20 and 28 examples**, including existing shared
content examples, default/custom health forwarding, invalid values and resource
guard behavior. Strict Ruby lint, module tidy, documentation tidy, syntax and
diff checks pass. No full RSpec suite is run. The human guide's `## Scenarios`
through EOF remains byte-identical, SHA-256
`2b62d19dc9537f7099c471b5b68f60ca4b7d2ed46e84f6d214efae8efd5311b7`.

Immutable local archives use independent copies, checked permissions, no hard
links and reverified manifests:

| Evidence under `/Users/dwelch/.codex/reports/` | Files / selected inputs | Manifest SHA-256 |
| --- | ---: | --- |
| `langflow-0770-public-boundary-failure-20261114` | 230 / 63 | `6d791ba876251972b814781be9c782c249dc4319fede4c58faf64e184dda58d2` |
| `langflow-0770-public-session-blocking-failure-20261114` | 243 / 60 | `c5323690755ef8400e87cdad163f1477d3115a164d2095b74aa12c129070d655` |
| `langflow-0770-qualified-20261114` | 385 / 65 | `3f2a9eb6a9999923d0e7c4d9fc82f30532b032eca8d6e420f8a37b3fb6022a25` |

The final archive also contains the native calibrations, preserved setup
failures and source-worker unit evidence. The qualified source hash is
`05a2b8bf69d9577f7311404a69e000472c9794def24ea58e21228a5bc2b3d9bc`.
Inventory: 5,179 source files, 240 registered owners, 265 pending documented
container reviews and zero stale reviews. Earlier Druid, FreeSWITCH, Superset
and WordPress deferrals remain open. The older remote Mettle `post/test/file`
timeout still has cause unverified.

## Self-review

- **Summary:** Genuine target controls, source corrections and repeated public
  execution qualify the covered command/session paths.
- **What looks good:** Native setup errors are distinguished from reproduced
  module defects; source bytes, readiness, remote effects and teardown are checked.
- **Concerns:** Scope is Linux amd64, one backend worker, configured superusers
  and the exercised payload families. Other versions, populated registries, TLS,
  URL prefixes, identity providers and validation-response/revocation diagnostics
  remain unqualified.
- **Suggestions:** Continue the remaining documented candidates; retain these
  failure archives and do not generalize the 1.8.4 command result to all releases.
