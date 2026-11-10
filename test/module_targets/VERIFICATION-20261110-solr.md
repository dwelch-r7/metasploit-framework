# Solr discovery and execution qualification

The selected checkpoint covers **129 runtime modules, 63 families and 860
functional cases**, adding three modules and twenty-eight cases to the
[Grafana checkpoint](VERIFICATION-20261109-grafana.md). Every selected profile
has exact counts, zero failures/pending/outside errors, current recorded input
hashes and owned teardown. The broader goal remains active. No PR was created
or full local RSpec suite run.

## Genuine versions, commands and sessions

The [Velocity lab](solr_velocity/README.md) uses official pinned Solr 8.3.0,
8.3.1 and 8.4.0. Actual runtimes are JRE 11.0.5, 11.0.15 and 11.0.6. Native
CLI/API controls establish real search operations, authentication, permissions,
affected execution, default-ineligible 8.3.1 and fixed 8.4.0 behavior. Each
Velocity profile performs forty-nine native commands and sixty-six HTTP checks.

The [backup lab](solr_backup/README.md) uses official pinned Solr 9.0.0/JRE
17.0.10 and fixed 9.4.1/JRE 17.0.11. Thirty-six native commands and sixty HTTP
checks independently verify actual class upload/filtering and execution. A
readable Java initializer is compiled with a pinned JDK; both exported class
hashes must match actual compiler output. Fixed 9.4.1 accepts the tested backup
requests but filters the class, with class-loading failure and no proof marker.
No backup-path rejection is claimed. Default 9.4.0 delivery also filters classes
and remains unqualified; the successful vulnerable deployment is 9.0.0.

| Final profile, run `20261109T234426-a1a012` | Cases/failures | RSpec seconds | Seed | Inputs |
| --- | --- | --- | --- | --- |
| `solr_velocity` | 10/0 | 388.682361 | 23905 | 54 |
| `solr_velocity_sessions` | 6/0 | 273.598521 | 46347 | 56 |
| `solr_backup` | 12/0 | 194.738685 | 44545 | 62 |

Eight generic command executions produce exact 32-byte files owned by `solr`.
Sixteen fresh sessions are opened and used: Java Meterpreter, Bash, Linux curl
staging and fetched Linux Meterpreter, across anonymous/admin contexts and
repeats. Native file/UID proof verifies execution as UID 8983. Independent SQL
checks real service/version and credential rows in a migrated disposable database.
Wrong/absent passwords, denied roles, missing paths, fixed/default-ineligible
versions and unrelated genuine HTTP are covered as each profile declares.

## Reproduced defects and setup corrections

| Retained invocation | Results | Classification |
| --- | --- | --- |
| `20261109T225934-4d6ab5` | 10/2, 6/0, 12/2 | Original sources; command corruption and initial listener assumption |
| `20261109T231923-e321c5` | Backup 12/2 | Corrected resource assertions, original source retains payload URL |
| `20261109T232449-af1b36` | 10/0, 6/0, Backup stops 5/1 | Download self-deletion/copy race; seven labels unexecuted |
| `20261109T234426-a1a012` | 10/0, 6/0, 12/0 | Complete final qualification |

Velocity's original requests expand `${IFS}` as a Solr macro and create empty
files. Independent real Solr controls echo the received parameter: default
expansion removes it; `expandMacros=false` preserves it and executes the exact
27-byte native marker. The control reconstructs the module wrapper and is
explicitly not labeled a recovered Framework wire capture. The owning repair
adds that parameter; original shell-variable command assertions remain intact.

Backup's cleanup override omits `super`. A corrected original baseline uses a
real session, closes it, and still retrieves a 250-byte ELF from the actual
retained fetch URL. Source regressions independently reproduce omitted payload
handler/socket cleanup. The owning repair calls the parent. Four final former
URLs return HTTP 404 with empty owned resources after four used fetch sessions.

The shared fetch service has a separate pooled lifetime: refs remain 2,3,4,5
until container teardown. Native Framework controls establish resource removal,
same-server reuse and the distinction from physical listener closure. Tests
require callback/stager closure and actual fetch-resource removal while recording
owner/refcounts. Shared pool closure is not claimed or changed. The first
original Backup failure observes exactly one used session; the later label
stops at its initial listener gate, not at exploitation.

FETCH_DELETE emits randomized 3..7-second deletion. The partial repaired run
races disappearance between temporary-file inventory and copy. Its failing
commands emit 7 and 3 seconds. The final family uses the existing bounded wait
helper within twenty wall-clock seconds to prove only the declared download
absent before copying. Other copy failures remain fatal. Six absence receipts
pass; all twenty-eight cases are replayed after the common spec changes.

## Verification, integrity and limits

Original focused runs are Velocity **8/1** and Backup **9/2**, each including
seven shared examples. Final combined **10/0**, repeated by the parent, contains
three owning regressions and those shared examples once. Three acceptance/unit
Ruby files lint clean. Changed module lint/tidy retains the identical nine
Velocity/one Backup findings. Module docs retain identical prior warnings and
the existing Backup documentation-path error. Human Scenarios remain unchanged.

The corrected-original Backup input set and first repaired set each have 62
keys and differ only in owning source. Subsequent common-fixture changes are
explicitly retained and requalified. The parent imports and byte-verifies all
**373** regular files of the final invocation, then verifies all 172 input
entries across the three profiles against current source. Raw revisions/paths
remain unchanged. The worker audits ten runner projects and forty-six recorded
volumes absent; the parent independently audits all three final projects and
their fourteen volumes. Native preparation/control teardown is separately retained.

The durable `solr-module-validation-20261110-a2adcc614e7` export contains every
original/failing/passing input set, native/source controls, SQL, state and copy
logs, source freezes and three separate commits. The parent independently rereads
all **2,481** checksums. `CHECKSUMS.sha256` digest:
`a2c288730b789ceeed0596b798fee47b9b613d9b5270ca1f25b910693a0108f9`.

Windows/x86, TLS, custom context paths, opt-in 8.3.1 parameter loading and other
runtime/configuration/repository combinations remain unqualified. Logical writer,
collection/configuration and temporary-file state is restored; revision counters
and logs are not rewound. No Internet callback or real account is used. No shared
runner/library/dependency/timeout change was needed. Declared hashes are not the
full dependency graph. Aggregate selection is `tmp/module-target-checkpoint-solr-current.json`;
WordPress admin remains unqualified, and Prometheus/ActiveMQ/capture work continues.
