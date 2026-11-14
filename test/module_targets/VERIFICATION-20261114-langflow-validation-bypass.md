# Langflow validation authentication boundary — 2026-11-14

All **21 functional examples and 42 public module calls pass**, with eight exact
command proofs and twelve complete session lifecycles. The campaign reaches
**241 modules qualified in covered paths, 293 profiles and 2,781 functional
examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_validation_bypass langflow_validation_autologin langflow_validation_guarded
```

The [lab guide](langflow_validation_bypass/README.md),
[recipes](langflow_validation_bypass/compose.yaml) and
[vendor record](langflow_validation_bypass/vendor.json) exercise
`exploit/multi/http/langflow_unauth_rce_cve_2025_3248` against genuine official
Linux amd64 images pinned by digest. Twenty installed source hashes per release
cover routing, validation, authentication and startup. No application endpoint
or implementation is replaced, and no model provider is required.

| Genuine configuration | Cases / public calls | Commands / sessions |
| --- | ---: | ---: |
| 1.2.0, automatic login disabled | 7 / 14 | 4 / 6 |
| 1.3.2, automatic login enabled | 7 / 14 | 4 / 6 |
| 1.3.2, automatic login disabled | 7 / 14 | 0 / 0 |

## Independent calibration and original failures

The [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/3xxx/CVE-2025-3248.json)
places the authentication bypass before 1.3.0. The
[vendor change](https://github.com/langflow-ai/langflow/pull/6911) adds an
authentication dependency to validation. Independent installed-source and HTTP
controls establish the distinction: protected 1.2.0 accepts anonymous validation
and even ignores an invalid bearer token, while other protected routes deny
access. Version 1.3.2 rejects invalid tokens, and disabling automatic login denies
anonymous validation. Authenticated native canaries still execute successfully.

Repeated default-argument and decorator canaries each write their exact marker
once with UID 1000/GID 0. Actual backend settings, PID and builtin names are
captured through the genuine validator. Before/after native results and complete
flow responses match: zero flows in the protected profiles and 32 starter flows
in the default profile. Python is 3.12.3, langflow-base is respectively 0.2.0 and
0.3.2, and MCP is 1.1.3. Lfx is absent. Version 1.2.0 has no lazy-loading setting;
1.3.2 uses its supported eager-loading configuration.

The original public replay completes eleven cases and eighteen calls with six
failures. Both accessible profiles execute two exact commands but retain a
backend-owned defunct child throughout eighteen restoration observations:
PID 419/PPID 16/birth 8450886 on 1.2.0 and PID 361/PPID 22/birth 8461353 on
1.3.2. The protected profile has four failures because denied payload submissions
silently appear successful. Native controls remain equal and all 24 teardown
queries pass, independently establishing working targets.

## Corrections and final verification

The check validates product/version metadata and posts comment-only Python.
That probe contains no imports or function definitions and executes no submitted
code. A valid anonymous response gives Appears before 1.3.0 and Detected on later
releases; an authentication denial gives a scoped Safe reason. The later default
login feature is explicitly outside this CVE's range. Framework AutoCheck allows
normal execution after Detected. Malformed metadata and expected transport
errors return reason-bearing Unknown.

Payload execution starts an isolated Python interpreter with DEVNULL streams.
A daemon worker waits for and reaps it, keeping payload globals, descriptors
and persistent session code outside the backend. HTTP 401/403 produce NoAccess;
missing responses and expected connection failures produce Unreachable; other
statuses, malformed validation structures and reported validation errors produce
UnexpectedReply. The established Python target, default payload and root-path
interface remain compatible.

Run `20261114T102108-1689af` completes in approximately **7 minutes 49 seconds**.
Controller, manager and independent observer exit zero. The first cold BOOT,
prompt and fresh metadata are observed independently; later consoles use only
the matching same-invocation seed. All **65 selected input hashes** match the
maintained source at qualification.

Every case repeats on the same selected owner. Commands cover AutoCheck on/off.
Python command shells and staged Meterpreter cover both fork settings. All twelve
sessions reach real readiness, perform remote identity/file operations, match
exploit/payload database provenance and pass a live backend health check. Each
closure removes its exact remote PID/birth identity, closes its database row and
restores the complete original process set with no callbacks, jobs, sessions or
defunct children. No discrepant-state retries or retained-process allowances are
needed. Protected cases verify Safe, normal AutoCheck abort, forced and disabled
AutoCheck denials, absent marker files and handlers closing without sessions.
Refused-port checks return Unknown. All eighteen native invocations exit zero.

Only three containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory, privileged mode
is disabled and published ports bind to localhost. OOM, OOM-kill and PID-limit
counters stay zero. All **24 independent teardown queries** pass; five subsequent
inventories are empty and the shared heavy-lane lock is free.

## Checks, evidence and limits

The same final focused source suite gives **27 examples / 26 expected failures**
on the original owner and **27 / zero failures** on the correction, with zero
outside-example errors. HTTP and Framework reporting are explicit unit doubles.
A real local interpreter probe repeats held payloads, verifies prompt return,
backend isolation, an explicitly inheritable descriptor staying out of the
child, worker completion and reaping. The container replay supplies genuine
target and session evidence. An initial reporting double needed fixture repair;
its diagnostic attempt is retained separately and excluded from defect evidence.

Harness corrections are classified separately: omit unsupported TARGETURI only
for this owner's metadata, and retain the refused-port category assertion while
allowing the corrected operation-specific reason. The parent audit initially
compared an intentional HTTP 403 flow denial with an authenticated HTTP 200 list.
It now checks denial statuses separately and compares both successful lists.
The initial failed audit is preserved; no selected runtime input changed.

Strict Ruby lint, module/documentation tidy, syntax, Compose preflight and diff
checks pass. No full RSpec suite is run. The human guide's `## Scenarios` through
EOF remains byte-identical, SHA-256
`b96bc53f43feb46e95c78e5fc889e28ff208fdc71c133b71872f1a669d63bf52`.

Immutable local archives under `/Users/dwelch/.codex/reports/` use independent
read-only copies, no hard links and reverified manifests:

| Archive | Files / selected inputs | Manifest SHA-256 |
| --- | ---: | --- |
| `langflow-3248-public-original-failure-20261114` | 300 / 65 | `636b0ba0bbfed010ecf09f9d0678340d9313308ed4c471042ce6d810420b56af` |
| `langflow-3248-qualified-20261114` | 364 / 65 | `0ba778b64e56ba89dcedec0d071aa2e2af53c8d4018a2bdfc032936aa0705920` |
| `langflow-3248-initial-unit-failures-20261114` | 5 / — | `f96dd0747d32dc42f5f522ee7d33a8dea2509418d941a15cfd27ae1d96c1e36a` |

The final archive includes installed-source captures, three standalone native
calibrations, original replay evidence and the final source-worker comparison.
Qualified owner source SHA-256:
`2ad7e79b68cd5fddab89c71d7fea1dc8b26ca8a32717e1e181727b8049c378d0`.
Inventory has 5,179 sources, 243 registered owners, 22 individual reviews,
258 pending documented container reviews and zero stale reviews. Registration
alone does not establish a pass. Existing Druid, FreeSWITCH, Superset and
WordPress deferrals remain open. The older remote Mettle `post/test/file`
timeout still has cause unverified.

Qualification covers these two one-worker Linux releases, three authentication
states and the exercised Python payloads. Other versions, platforms, replicas,
TLS, URL prefixes, providers and stageless payloads remain unqualified.

## Self-review

- **Summary:** Genuine controls and repeated public execution qualify the
  covered validation-bypass and later authentication paths.
- **What looks good:** Retained children and false-success denials have original
  evidence; commands, session closure and exact process restoration now pass.
- **Concerns:** Qualification remains bounded to the listed configurations.
  Corrected fixture and audit errors are excluded from module defect evidence.
- **Suggestions:** Continue the remaining valuable candidates and retain the
  separate host requirements and unqualified paths.
