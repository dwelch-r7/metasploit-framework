# Native APISIX route commands and sessions

Verified 2026-11-19 against source SHA-256
`2ad0a220e70c0a01e9310960140fa5412d8b2fc12f9bcef558474d7f7115f4cc`.

| Profile | Raw cases | Owner cases | Native handler cases | Owner sessions used/closed |
| --- | ---: | ---: | ---: | ---: |
| `apisix_2120_batch_open` | 11/0 | 9/0 | 2/0 | 3 |
| `apisix_2121_direct` | 11/0 | 9/0 | 2/0 | 3 |
| `apisix_2120_direct` | 6/0 | 6/0 | 0 | 0 |
| `apisix_2121_batch` | 5/0 | 5/0 | 0 | 0 |
| Total | 33/0 | 29/0 | 4/0 | 6 |

Four independent handler sessions are also used and closed. These 33 maintained
cases add one owner and four profiles, reaching **312 runtime owners in covered
paths, 647 qualified profiles and 4,687 historical functional cases**. Separate
diagnostics and the shared-helper regression add no campaign counts.

The [fixture guide](apisix/README.md) and
[functional spec](../../spec/modules/exploits/multi/http/apache_apisix_api_default_token_rce_target_spec.rb)
provide four pinned, stock APISIX/etcd profiles. The positive session profiles
also use the existing real Framework reporting PostgreSQL fixture. The host
uses macOS, Ruby 3.3.13, the existing bundle and Python standard library. No
package or replacement application code is installed in the target images.

## Target and independent controls

The native controls verify APISIX versions and bundled source hashes, real
administration access, exact command execution as the stock nobody UID 65534,
and route/file cleanup before owner verdicts. Independent Lua decimal-byte
construction executes each same-byte command before the module. A pre-existing
route named index must survive every owner case. Append-only proofs detect
multiple execution rather than masking it through file replacement.

Batch-enabled 2.12.0 with allowed administration access qualifies batch delivery;
2.12.0/2.12.1 with the batch plugin disabled exercise direct script delivery.
Restricted-admin 2.12.1 supplies genuine denial and no-mutation controls. The
[Apache CVE-2022-24112 advisory](https://www.openwall.com/lists/oss-security/2022/02/11/3)
fixes the batch IP bypass in 2.10.4/2.12.1. It does not establish that an
administrator with valid direct access can no longer execute route scripts.
The [older CVE-2020-13945 advisory](https://seclists.org/oss-sec/2020/q4/187)
covers 1.2-1.5 default-token exposure after access rules were removed; those
versions are not represented by these fixtures.

## Repairs and retained failures

Five focused changes correct effective inner-response access checks, byte loss
in Lua strings, unsafe global route replacement, foreground session blocking,
and immediate triggers before the data-plane route becomes visible. Allocated
route cleanup verifies ownership and acknowledges actual deletion; failed
cleanup retains its record for a later attempt. Existing routes remain intact.

The session failure was genuine: a real owner Bash session opened, was used and
closed, while its foreground command blocked the worker and cleanup API. The
route remained in etcd. The detached exact-operand repair made API cleanup
possible while the session remained open. A subsequent replay created routes
with HTTP 201, then received HTTP 404 from their immediate triggers. The same
source later opened and cleaned a real session, so one passing replay was not
accepted as reliable qualification.

The activation repair uses a per-route nonce. A non-executing marked HTTP 404 confirms
the filter is loaded; ordinary/wrong-token requests cannot execute it. Bounded
polling retries only unmarked route misses. Then one explicit execution request
is sent, with no retry even if its reply is missing. Independent stock controls
verify repeated probes and wrong-token requests leave the proof absent, followed
by one exact appended marker from one real trigger. The private real-Lua counter
and maintained focused cases separately test failure paths and one invocation.
The actual session matrix also exercised delayed visibility: Bash needed 19 safe
probes and a Netcat repeat needed 17; each then sent one execution request.

The root run passes **95 module cases plus seven automatically loaded acceptance
formatting cases (102/0 raw)**. The identical 95-case activation regression suite
passes 95/0 after recording 19 failures on the immediately preceding source.
Its final-source Lua counter passes 6/6. Ruby lint and module tidy retain the one
inherited `Lint/ModuleDefaultPayload` offense; no new offenses remain. The actual
automatic PHP choice and absent stock runtime justify retaining the working Bash
default. New Ruby helpers and the functional spec are clean; module-doc tidy and
Python syntax checks pass. No dependency is added.

## Qualification limits

Stock restricted-admin 2.12.0 produced both native bypass success and native HTTP 403
on fresh instances. Real-IP headers with different capitalization and the
installed HTTP library's normalization offer an explanation; exact worker iteration order was
not captured. Restricted 2.12.0 bypass remains unqualified. The open-admin batch
profile is explicitly not proof of that bypass.

The existing Bash default remains because the real automatic chooser selected a
PHP Meterpreter adapter while the stock image lacks PHP and Python. Bash and
Netcat are present and use the public compatible-payload catalogue. Other
runtime-dependent payloads, bind sessions, releases, ARM, TLS, custom prefixes,
nondefault Admin API key roles, concurrent route edits and external failure injection remain unqualified.

## Shared controls and lifecycle

Two small hooks preserve the existing Kafka/Kong UID 100 behavior while APISIX
uses its observed worker UID 65534 and executes SDK controls under that user.
The complete Kafka/Kong five-profile regression passed 45/0, with 25 actual sessions
used and closed; all 35 observed Docker resources were independently absent.
Its 722-entry capsule is apisix-shared-regression-20261119T201409, manifest
8281f7cac81942fd72150e24dd9b8b6edb1c17feb54615d5a61927b27faacd78.
It adds no campaign counts. Shared inputs have not changed since that replay.

All stacks are namespaced, capped and serial under the shared heavy lock.
Cleanup runs after success, failure or interruption and exact IDs are checked
for absence. The distroless etcd image has no cat: Engine health/restart/OOM
observations are separate from application/reporting kernel counters.

Existing human Scenarios remain byte-identical: 867 bytes, SHA256
cbe027ebb5ac8426c0643dba3dfd08cc86eb4a40861b1be21e61d6b90c79e99a.
The full RSpec suite was not requested or run. No PR is created; the broader goal
remains active.

## Maintained replay evidence

```sh
MODULE_TARGET_NAMESPACE="apisix-$$" bundle exec ruby tools/dev/run_guarded_module_target_tests.rb apisix_2120_batch_open apisix_2121_direct apisix_2120_direct apisix_2121_batch
```

The parent audit verifies **33/0**, 12 exact owner commands, 23 independent exact
commands, 652 native assertions and 138 zero OOM/PID-limit counter readings.
All 91 recorded inputs remained unchanged during the replay. Before publication,
four unused provisional config copies were removed; none was referenced by the
resolved Compose configuration, which remains identical. All 87 published test
inputs match their tested hashes. Every session has one actual reporting row in its unique workspace, correct owner/payload metadata, a real
remote proof and closure timestamp. The API and route inventory are checked
before owner sessions close; child processes, FIFOs, proof files and listeners
are checked afterward.

Only three capped containers run at once. All 20 observed containers, networks
and volumes are independently absent. Actual image IDs verify Linux amd64 for
both APISIX releases, etcd and reporting PostgreSQL. The sealed local capsule
`apisix-maintained-20261119T211914` contains 561 entries; its SHA256SUMS digest
is `5b26c871f2a27c7ac977db84ecda14fb2ccb75aa6214b4c7bab72cbd9a6115a0`. It retains tested sources,
native/console/wire/SQL records, parent audit results and exact cleanup receipts.

Earlier failed owner sessions, independent controls and the successful Bash diagnostic
on the same source remain in `apisix-activation-diagnostics-20261119T210019`
(manifest `110ae03a56ca4d44d8a71bf32fdef3217c0fce37b9b1685e6dfa2db06e88583b`).
Independent stock nonce controls remain in `apisix-nonce-controls-20261119T210735`
(manifest `44e672a3f8419279b4a227f5ea93d7b1449a891b0807fd8738e70ab2ed600fd5`).
The separate repair capsule `apisix-route-activation-20261119T211848` retains the
95-case before/after pair and final-source counter (manifest
`3db2eaccbc806321025b36ab06b3a3ddb18513ee6df50b98cae71ca9535644f3`).
Those diagnostics do not add owner qualification beyond the maintained matrix.

## Summary

One owner has four maintained profiles proving the covered administration, exact
command, session, reporting, repeat and denial paths.

## What looks good

Independent genuine targets, actual bytes, session use/reporting and physical
cleanup provide distinct evidence rather than treating successful setup as a
module pass.

## Concerns

Restricted 2.12.0 bypass and the other limits above remain unqualified.

## Suggestions

Investigate restricted-bypass header ordering separately, retaining the strict
native prerequisite and avoiding changes that turn setup failures into passes.
