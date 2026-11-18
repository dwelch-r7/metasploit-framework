# Native SuiteCRM export collection, 2026-11-18

`auxiliary/gather/suite_crm_export_sqli` passes **16/0** across official SuiteCRM
7.12.5 and fixed 7.12.6, with zero pending cases or errors outside examples.
This adds one runtime owner, two profiles and sixteen cases, reaching **301
runtime owners in covered paths, 613 qualified profiles and 4,299 historical
functional cases**. The earlier 16/0 replay is retained but not counted twice.
The broader campaign remains active. No PR is created.

The [shared target guide](suitecrm/README.md) gives the namespaced guarded command,
resource caps, fixture credentials and explicit limits. Three capped services run
serially: app 768 MiB/1 CPU, MariaDB 384 MiB/0.5 CPU and reporting PostgreSQL 384 MiB/0.25 CPU,
with 128 PIDs each. Completed stacks are removed immediately. Only task-created
unused containers up over an hour are eligible for campaign cleanup; other
namespaces are preserved.

## Native prerequisites and setup corrections

The official release ZIPs include vendor dependencies and are SHA-256 verified.
PHP 7.4.33 and MariaDB 10.6.19 base images are digest-pinned. A genuine silent
installer, BeanFactory and User APIs create two users and one Account without
replacing application or module handlers. Independent HTTP controls verify
login, About, ordinary Account CSV, repeated Boolean export contrasts and actual
login-form denial for bad credentials. The official export-handler hash and
selected native user/Account snapshots match before and after each profile.
The vulnerable export returns an Account only for the true expression; fixed
7.12.6 keeps ordinary export working and returns header-only CSV for both.
The original [export advisory](https://blog.exodusintel.com/2022/06/09/salesagility-suitecrm-export-request-sql-injection-vulnerability/)
and [vendor release notes](https://docs.suitecrm.com/admin/releases/7.12.x/#_7_12_6)
provide the source context; runtime conclusions come from the captured controls.

Initial stale Debian package metadata, native explicit-password seeding and
Python HTTP-recording defects are setup failures, without owner qualification.
The build now uses signed dated snapshot indexes. An initial owner attempt also
had an undersized command bound without OPcache and an unregistered TARGETURI;
its timeout and outside-example error are not module verdicts. Enabling standard
OPcache, removing that fixture option and allowing legitimate blind-query time
produces a complete unchanged-owner baseline: **2 examples, 2 failures, zero
outside errors**, with both complete native hashes recovered and cleanup passed.

## Confirmed owner defects and separate repairs

The valid baseline reports `Vulnerable` from version information alone and ignores
`COUNT=1`, selecting and persisting both users. Separate worktrees repair these
independently. Passive detection now returns reason-bearing `Appears`; missing
authentication/version evidence and expected connection errors return `Unknown`.
The parser scopes SuiteCRM's About element instead of confusing its embedded
SugarCRM version. The 7.12.6 boundary remains `Safe`.

COUNT now limits deterministic distinct username selection before aggregation,
using comma-free SQL required by this endpoint. Default 3 is preserved; 0/unset
means all. Invalid limits fail before the username extraction query. The helper
return shape remains unchanged. Focused synthetic regressions reproduce check
21/18 and count 15/9 before their respective repairs; combined candidates pass
**36/0**. Only the 7.12.5 About fragment is a native response fixture; other focused
response/version/error cases are synthetic. Syntax, module tidy and changed Ruby
lint pass with zero offenses. The module-document checker retains ten baseline
warnings with zero new warnings. The static inventory has 5,179 sources, 4,293
pending selectable candidates, 222 pending documented container hints and zero
stale reviews. Existing human-written Scenarios are unchanged.

## Final functional evidence

Run `20261118T190751-ecb7c3` passes 8/0 per profile with **49 unchanged declared inputs**,
20 console owner requests and 112 actual source trace events. There are
44 independent native HTTP captures and 24 zero-valued memory/PID event captures.
The vulnerable profile takes 230.79s and the fixed profile 32.05s, excluding build/startup.

The eight cases cover repeated manual check, COUNT=1 twice with AutoCheck on/off,
COUNT=0, the actual default, wrong credentials with AutoCheck on/off, negative
COUNT and an unavailable endpoint. Each successful collection must return exactly
the expected selected usernames and persisted 60-byte bcrypt hashes, credential
cardinality, type, JtR format, origin module and endpoint. The repeated configured
console module keeps its identity and does not add credential rows; Framework
may replicate it for actual execution. The fixed release refuses normal collection
through AutoCheck without entering the owner run body. Sessions/jobs remain
empty, selected native state is unchanged and both owned teardowns pass.

A review of the first repaired 16/0 replay found harness assertions to strengthen:
require login-form/route proof for wrong credentials, exact credential row counts,
actual default COUNT and traced selected usernames. That immutable replay was
sealed before those edits; the final 16/0 replay exercises the stronger assertions.
Independent inspection confirms absence of all **62 Docker objects** from this
cohort's manual probes and functional attempts. No task containers remain and
no unrelated container was removed.

## Limits and investigation

Only the root application path, two releases, this PHP/MariaDB combination and
seeded ASCII usernames are qualified. Other releases, URL prefixes, TLS, other
engines, special usernames and nonadministrator collector authentication remain
separate native work. No session or code-execution claim applies to this collector.

The existing CVE reference remains unchanged and needs separate investigation.
The 2022 primary export advisory lists CVE Pending and points to 7.12.6, while the
[official CVE-2023-5350 record](https://www.cve.org/CVERecord?id=CVE-2023-5350)
references a 7.14.1 fix. The exact mapping has not been established; the selected
export source change and native behavior are verified independently. Local runtime
success does not imply fork CI execution or success. No full local suite was run.

## Sealed local evidence

- Final runtime: `suitecrm-functional-20261118T190750`, 126 files; manifest
  `20d8c8f0c05f4ce4d3a1f050cd24436487d5122bd3ecb97e062105dc739401f2`.
- Valid unchanged baseline: `suitecrm-functional-20261118T184213`, 77 files; manifest
  `1c0307586a5cca23550a1ed7efeb9876b2eb8891f69248d915b7c0dd77957a5b`.
- First repaired replay: `suitecrm-functional-20261118T190033`, 126 files; manifest
  `f16513e3eeb7b5c07596858371ffec473331911fc6ad47810cb655dbb78b1829`.
- Separate check repair: 95 files; manifest
  `f00a3d56287086d84052d85fbb6282a1c2394964a88e5d6960a94507f6a68a78`.
- Separate COUNT repair: 36 files; manifest
  `c63d68eb218cabc67f234025510eb94bdb6f495b16cec05f60960c04d38e5a6c`.

Capsules retain exact declared inputs, native byte captures, commands, source
traces, persisted reporting evidence, resource events and SHA256 manifests
outside Git. The module and reusable Compose/spec/helper/guide files live here.
