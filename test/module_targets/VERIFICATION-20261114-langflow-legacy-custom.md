# Langflow legacy custom components — 2026-11-14

All **15 functional examples and 30 public module calls pass**, with four exact
command proofs and six complete session lifecycles. The campaign reaches
**240 modules qualified in covered paths, 290 profiles and 2,760 functional
examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_legacy_custom langflow_legacy_custom_protected
```

The [lab guide](langflow_legacy_custom/README.md),
[Compose recipe](langflow_legacy_custom/compose.yaml) and
[vendor record](langflow_legacy_custom/vendor.json) qualify
`exploit/multi/http/langflow_unauth_rce_cve_2026_0769` against the genuine official
Linux amd64 Langflow 1.3.2 image, pinned by digest. Installed versions are Python
3.12.3, langflow-base 0.3.2 and MCP 1.1.3; lfx is absent. Sixteen source hashes
cover the actual component loader, endpoint, authentication and startup. No
application endpoint or implementation is replaced. No AI provider is needed.

| Genuine configuration | Cases / public calls | Commands / sessions |
| --- | ---: | ---: |
| Automatic login enabled | 8 / 16 | 4 / 6 |
| Automatic login disabled | 7 / 14 | 0 / 0 |

## Independent target calibration

Offline source capture establishes the legacy loader's actual behavior:
`prepare_global_scope` executes definitions and `build_class_constructor`
executes the component class again. The endpoint creates fresh scopes, so a
local `_fired` list does not span the whole request.

Independent native controls submit a benign component and repeat decorator
canaries with omitted and empty frontend nodes. Each canary writes its marker
**three times**, with UID 1000/GID 0, under both authentication configurations.
Anonymous calls work with automatic login enabled; disabling it produces HTTP
403. Invalid bearer tokens produce 401, while a valid fixture token still
executes native controls. These observations establish working targets before
attributing failures to the Framework owner.

A separate component writes actual backend settings, PID and builtin names.
Its computed display name in the genuine HTTP response must match that PID;
the cleanup proof is not inferred from an invented response shape. The complete
flow responses remain unchanged: 32 starter flows in the open profile and an
empty protected registry. Native temporary files are removed after every proof.

## Original defects and corrections

The unchanged owner's public open-profile replay stops after two cases and
three calls. Its first command appends the exact marker three times; all 33
subsequent reads confirm those bytes. A defunct child, PID 402/birth 8212345,
remains owned by backend PID 22 throughout the bounded restoration check.
The protected replay runs seven cases and ten calls, with four failures because
HTTP 403 is reported as generic Failure::Unknown. Native before/after results
match in both profiles, and all sixteen independent teardown queries pass.

The corrected owner claims one randomized, non-identifier builtin key across
loader scopes. A daemon worker runs the encoded payload in a separate Python
interpreter with DEVNULL streams and waits for it. This preserves HTTP
responsiveness and avoids leaving payload children owned by the backend.
Each attempt records its original target and backend PID. Cleanup retires a
guard only after a response with the matching randomized prefix and worker PID;
unconfirmed records remain available for retry. The generated component also
returns a valid Data value. Public payload architecture and options remain.

HTTP 401/403 now produce NoAccess, absent responses and expected transport
errors produce Unreachable, and other non-200 responses produce UnexpectedReply.
Malformed versions return reason-bearing Unknown without raising. Only the
known 1.3.2 release receives Appears; other versions receive Detected without an
unsupported fixed-version claim. The
[CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/0xxx/CVE-2026-0769.json)
names 1.3.2 as affected and leaves other versions unknown; the
[original disclosure](https://www.zerodayinitiative.com/advisories/ZDI-26-035/)
identifies no fixed release. Passive version detection does not establish a
deployment's authentication policy.

## Final genuine verification

Run `20261114T092632-e84f27` completes in approximately **4 minutes 55 seconds**.
The replay controller, manager and independent observer all exit zero.
The first actual cold BOOT, prompt and fresh metadata are independently observed;
the second console uses the normal same-invocation seed with matching bytes.
All **63 selected input hashes** match the maintained source at this checkpoint.

Every case repeats on the same selected owner without another `use`. Exact
commands run with AutoCheck on and off. Python command shells and staged Python
Meterpreter cover both fork settings. Every session reaches a real ready event,
performs remote identity/file operations, matches exploit/payload database
provenance, passes a live backend health check and closes its database row.
Shutdown removes its exact remote PID/birth identity and restores the complete
original process set, with no callbacks, jobs, sessions or defunct children.

The protected cases verify denied commands without marker files, denied shell
and Meterpreter payloads without sessions, passive version detection, refused
ports and missing paths. All ten native probe invocations exit zero. Full
before/after results, flow responses and backend builtin-name sets match.
Per-case checks reject guard-cleanup warnings. Every accepted idle state matches
the exact original process identities; this replay needs no discrepant-state
retries. No retained PID, zombie or callback allowance is introduced.

Only three containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory and published
ports bind to localhost. Privileged mode is disabled. OOM, OOM-kill and PID-limit
counters remain zero. All **sixteen independent teardown queries** pass for
exact resources, project labels and the global inventory. Five later inventories
are empty and the shared heavy-lane lock is free.

## Checks, evidence and limits

The focused source suite passes **19 examples**. Four original regressions were
independently completed and failed as expected, including a local interpreter
probe that observed three executions. HTTP and Component/Field APIs in those
unit cases are explicit doubles; the container replay supplies genuine target
and payload-session evidence. An additional original-source unit comparison
failed inside the RSpec JSON reporter and is excluded from module evidence.
Its diagnostic output remains preserved.

Strict Ruby lint, module/documentation tidy, syntax and diff checks pass. The
recipes resolve to the intended three capped roles, and generated native
component variants parse. No full RSpec suite is run. The human guide's
`## Scenarios` through EOF remains byte-identical, SHA-256
`123ed44883752de7ad40abd70d831aee77eac51aa507e24a80000d991285c3ec`.

Immutable local archives use independent copies, read-only permissions, no hard
links and reverified manifests:

| Evidence under `/Users/dwelch/.codex/reports/` | Files / selected inputs | Manifest SHA-256 |
| --- | ---: | --- |
| `langflow-0769-public-original-failure-20261114` | 256 / 63 | `90dab6fdc0855076907ce127ff7329fa75a0b70b6f555ad36030cd0314c6aff1` |
| `langflow-0769-qualified-20261114` | 285 / 63 | `623c9bab286fb6fd94c585f6ed73c53a6ac3274b082fa39cea991cbd70da6e98` |
| `langflow-0769-prepared-source-fix-20261114` | 27 / 3 | `95ecd175c0084e92ad73ac5c296bfea002b7738329689227bb1b10f1e3fb0be6` |

The final archive also includes installed-source captures, both standalone
native calibrations, original regression evidence and source-worker checks.
Qualified module source SHA-256:
`c07ad4e77fa6ce3de1f5727ab1d079ec74f9a97cc0ef5d45acf02f8665f3d723`.
Inventory has 5,179 sources, 242 registered owners, 22 individual target
reviews, 259 pending documented container reviews and zero stale reviews.
Registration alone does not establish a passing result.
The four separate host requirements are documented in the
[source review](REVIEW-20261114-container-host-requirements.md); those reviews
add no functional passes. Existing Druid, FreeSWITCH, Superset and WordPress
deferrals remain open. The older remote Mettle `post/test/file` timeout still
has cause unverified.

Scope is the pinned one-worker Linux 1.3.2 image, these authentication policies
and the exercised Python payloads. Other versions, platforms, replicas, TLS,
URL prefixes, providers and stageless payloads remain unqualified. A worker PID
is not a cross-replica identity guarantee. The broader campaign remains open.

## Self-review

- **Summary:** Independent target controls and repeated public execution qualify
  the covered legacy custom-component and protected-target paths.
- **What looks good:** Triple execution and a retained backend child have real
  before evidence; exact commands, session closure, process identity, guard
  cleanup and flow preservation have passing after evidence.
- **Concerns:** Qualification is bounded to one worker and the exercised payloads.
  The failed reporter observation is not treated as a module failure.
- **Suggestions:** Continue the remaining valuable candidates and preserve the
  documented separate-target requirements and unqualified paths.
