# Langflow public-flow build — 2026-11-14

All **17 functional examples and 34 public module calls pass**, with four exact
command proofs and six complete session lifecycles. The campaign reaches
**242 modules qualified in covered paths, 295 profiles and 2,798 functional
examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_public langflow_public_fixed
```

The [lab guide](langflow_public/README.md),
[affected recipe](langflow_public/compose.yaml),
[fixed recipe](langflow_public_fixed/compose.yaml) and
[vendor record](langflow_public/vendor.json) exercise
`exploit/multi/http/langflow_unauth_rce_cve_2026_33017` against genuine official
Linux amd64 images pinned by digest. Both applications require login for normal
API access. Public build requests have no authentication token. No application
endpoint or implementation is replaced, and no model provider is required.

| Genuine configuration | Cases / public calls | Commands / sessions |
| --- | ---: | ---: |
| 1.8.4, known public flow | 10 / 20 | 4 / 6 |
| 1.9.0, stored-definition boundary | 7 / 14 | 0 / 0 |

## Independent calibration and original failures

The [vendor advisory](https://github.com/langflow-ai/langflow/security/advisories/GHSA-vwmf-pq79-vjvx)
and [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/33xxx/CVE-2026-33017.json)
identify supplied public-flow definitions as the pre-1.9.0 vulnerability.
Installed-source capture verifies 41 source hashes on 1.8.4 and 42 on 1.9.0,
including routing, public-flow identity, build events and component execution.

Seven native controls per release establish working targets before Framework
execution. Missing cookies return 400, private and unknown flow UUIDs return
403, and malformed IDs return 422. Repeated 1.8.4 public builds execute the
supplied definition with exact one-write UID 1000/GID 0 canaries. Version 1.9.0
instead executes the stored definition. Authenticated supplied-data execution
still works on both, distinguishing the fixed public boundary from a broken
component or backend. Each successful job reaches a finite end event, a valid
vertex and the expected Data output. Temporary files and fixture flows are
removed, and the complete original registry is restored.

The unchanged module's affected replay stops after two cases and three calls.
Its first command writes the exact marker once but leaves backend-owned zombie
PID 381/PPID 43/birth 8695504/UID 1000 across 21 observations. The fixed-target
replay runs seven cases and ten calls with four explicit-failure contract
mismatches: it acknowledges submitted data without consuming build completion.
Both full native before/after results remain equal, both fixture registries
return to empty, and all sixteen independent teardown queries pass.

The original fixed-target command absence assertions were not reached because
their failure-category assertions ran first. Do not infer original owning
marker absence from cleanup. After sealing that run, the fixture was strengthened
to observe and journal absence before checking the unchanged failure category.
Independent native controls supply the original stored-versus-supplied proof.
Private/unknown owning-module cases were not reached in the original replay.

## Corrections and final verification

The component output method starts the encoded payload in a separate interpreter
with DEVNULL streams. A daemon worker waits for and reaps it. Class preparation
does not start payload execution, and no shared execution guard is introduced.
The method returns a fresh per-attempt proof while a session can remain active.
Payload globals, backend descriptors and forks stay outside the persistent
Langflow interpreter.

The module follows the genuine returned job ID through bounded public-event
polling. Delivery requires finite completion and a valid vertex matching the
submitted node, output name and fresh proof. Stored-flow results, failed vertices,
error events and malformed or unfinished jobs produce UnexpectedReply. Missing
replies and expected transport failures produce Unreachable; HTTP 401/403 produce
NoAccess. Version checks handle malformed metadata and expected transport errors
without raising. The public Python target, payload choices and FLOW_ID/TARGETURI
interface remain compatible. BuildTimeout controls the retry window; an in-flight
request remains bounded separately by HttpClientTimeout.

Run `20261114T110212-26a45d` completes in approximately **4 minutes 55 seconds**.
Controller, manager and independent observer exit zero. The first genuine cold
BOOT, prompt and metadata are observed independently; the second console uses
only the matching same-invocation seed. All **61 selected input hashes** match
the maintained source at qualification.

Every case repeats on the same selected owner. Exact commands cover AutoCheck
on/off. Python shell and staged Meterpreter sessions cover both Meterpreter fork
settings. All six sessions reach real readiness, perform remote identity/file
operations, match exploit/payload database provenance and pass a live backend
health check. Closure removes the exact remote PID/birth identity, closes the
database row and restores the complete original process set. No callbacks, jobs,
sessions, retained children or discrepant-state retries remain.

Affected cases also cover private/unknown flow denials, refused ports and a
missing application path. Fixed cases cover Safe, normal AutoCheck abort and
forced or disabled-AutoCheck attempts without payload execution. Six explicit
post-response command-absence proofs are recorded. All **62 native invocations**
exit zero: four full verifications, six live-health checks, fifty complete
registry checks and two fixture-cleanup checks. The complete records of both
fixture flows remain identical through execution and are deleted back to the
complete original registry.

Only three containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory, privileged mode
is disabled and published ports bind to localhost. OOM, OOM-kill and PID-limit
counters stay zero. All **sixteen independent teardown queries** pass. Five
subsequent inventories are empty and the shared heavy-lane lock is free.

## Checks, evidence and limits

The identical focused source suite gives **34 examples / 27 failed expectations**
on the original owner and **34 / zero failures** on the correction, with no
pending or outside-example errors. Those 27 expectations are not 27 distinct
defects; they include new delivery and diagnostic contracts. HTTP, reporting,
generated names and minimal Python Component/Output/Data APIs are explicit
doubles. The real local Python probe executes actual emitted code and encoded
payload stubs twice: the correction returns while held, isolates an explicitly
inheritable socket descriptor, preserves backend builtins and reaps both children.
Both original/fixed interpreter probes themselves exit zero.

Strict changed-Ruby lint, module/documentation tidy, syntax, Compose and diff
checks pass. Three initial spec-only layout offenses were corrected and their
diagnostics retained. No full RSpec suite is run. Root added the maintained lab
crosslink after integrating the byte-exact worker files and reran documentation
tidy. The human guide's `## Scenarios` through EOF remains byte-identical:
`bb56bf6de2639af33e550a64adb93d99c249556b68263f6732022590489e4e81`.

Immutable local archives under `/Users/dwelch/.codex/reports/` use independent
read-only copies, no hard links and reverified manifests:

| Archive | Files / selected inputs | Manifest SHA-256 |
| --- | ---: | --- |
| `langflow-33017-native-calibration-20261114` | 69 / 18 | `22e8d952510fcebcacec6eaad6fd55d7326370289e7ea6efb1bd76efd89f6f3b` |
| `langflow-33017-public-original-failure-20261114` | 254 / 60 | `eed32c2dfd19135511f7c33aeba1ed5c0a9e0dd6098b27bf78bb6d7b08515720` |
| `langflow-33017-qualified-20261114` | 323 / 61 | `5a40c7bd85a9eb1dc3ebf0ba5df2b6e5bf30ccab95c8adb8d3f147bb2004b30a` |

The final archive includes original native/source evidence, source-worker
comparisons, the fixture observation correction and independent qualification
audit. Qualified owner source SHA-256:
`5f6ac438db04f94c0225e4e23376ae42cbc7af770ae2169878d6fe96bea94998`.
Inventory has 5,179 sources, 244 registered owners, 22 individual reviews,
257 pending documented container reviews and zero stale reviews. Registration
alone is not a pass. Existing Druid, FreeSWITCH, Superset and WordPress deferrals
remain open. The older remote Mettle `post/test/file` timeout still has cause
unverified.

Qualification covers these two one-worker Linux releases, known public flows
and the exercised Python payloads. Other versions, platforms, replicas, TLS,
URL prefixes, providers and stageless payloads remain unqualified. Other public
flow CVEs and their credential/creation modes need separate evidence.

## Self-review

- **Summary:** Genuine controls and repeated public execution qualify the
  covered public-flow definition and fixed-target paths.
- **What looks good:** Original retention has direct evidence; exact commands,
  completed jobs, session closure and complete process/registry restoration pass.
- **Concerns:** Qualification remains bounded to the listed configurations.
  The original marker-absence limitation is preserved explicitly.
- **Suggestions:** Continue remaining valuable candidates, including separate
  existing-flow and credential-created-flow behavior and cleanup ownership.
