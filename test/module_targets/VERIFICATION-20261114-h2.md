# H2 console verification — 2026-11-14

## Summary

**231 modules qualified in covered paths, 269 profiles and 2,596 functional
examples.** Inventory: 5,179 source files, 233 registered sources, 272 pending
documented container hints and zero stale reviews. The broader campaign remains
incomplete. No pull request was created.

This checkpoint qualifies `exploit/linux/http/h2_webinterface_rce` through the
[shared H2 lab](h2_console/README.md). It fixes connection-only vulnerability
claims, silent HTTP 200 authentication/SQL failures, blocking launch and skipped
cleanup, legacy version parsing and excessively long SQL error output. The new
shell command path quotes payload URLs safely. This is administrator feature
abuse; these three H2 versions are not labelled an affected/fixed release
boundary.

Frozen replay **`20261114T010323-ceb0e7` passed 42/42 cases**, with zero pending
or outside-example errors. It made **96 public module calls**, proved **18 exact
commands** and completed **12 real session lifecycles**. Controller, manager and
independent observer exited zero. RSpec totals 598.4 seconds; complete serial
setup/teardown took 656.4 seconds. Initial compilation and calibration are separate
costs. All **61 selected input hashes** remain exact after the lab/guide commit
`132ec3649b151400e4be1d7936b0463482e78141`.

| H2 version | Profile | Cases | RSpec seconds |
| --- | --- | ---: | ---: |
| 2.1.214 | `h2_console` | 14 | 228.6 |
| 2.0.204 | `h2_console_204` | 14 | 190.9 |
| 1.4.199 | `h2_console_199` | 14 | 178.8 |

Each profile covers three connection checks (blank/admin/restricted), bad
credentials and database-creation policy through check/AutoCheck, three command
paths, two failures with AutoCheck disabled, two real payload/session families,
and refused-port/missing-path checks. State-changing paths run twice. An existing
database succeeds on the no-create listener. A semicolon in the payload URL
checks real shell quoting. GETVERSION works on all three releases.

## What looks good

The target runs unmodified, checksum-verified Maven H2 JARs on a digest-pinned
Java 8 JDK. Bootstrap code seeds a canary and restricted account, then starts
real vendor JDBC and web servers. Native JDBC and HTTP controls independently
verify version, SQL results, alias creation/call/drop, authentication, restricted
permissions and both creation policies before and after owner execution.

Owning `check`/`run` commands execute in a genuine console, without replacement
of module methods or network responses. Exact command bytes and UID are read
from the target filesystem. Bash and the default Python Meterpreter perform
real remote operations, with unique session identities and persisted database
records. Aliases and downloaded scripts are absent while sessions remain live;
remote shutdown, PID birth, socket, job and database closure checks pass.

Source changes use independent validated SQL requests. Java reads the script
before unlinking it and starts it with detached streams, avoiding the open/unlink
race and long-lived-session output wait. FileDropper remains a fallback;
no-session commands retain native cleanup. Human error messages preserve the
numeric code, while full native SQL errors go to the developer log.

Initial source repair `982251887c1bead484708306151d2e53cd1bdae9` and output
follow-up `6de77ddf1845ebf98d20af136cd2ca4fa7a22921` were imported as
`efccaf673db9012d1040a90d4d023121c1034143` and
`67107786faad8df21da1e7ba81ef9ff742678687`. The first identical 39-example
host suite reproduces 26 failures on the original owner and passes after repair. The expanded
40-example suite reproduces its one new output failure on the predecessor and
passes current source: 33 owner examples plus seven loaded support examples.
All original 39 examples remain byte exact in that expansion.

New host/functional specs and the download helper pass strict RuboCop with
zero offenses. Owner strict lint exits 1 and msftidy exits 2 for the same two
original offenses: default PAYLOAD and duplicate RPORT. No new offense or module
tidy diagnostic was introduced. Before/after documentation tidy, syntax and
diff checks pass. The original human Scenarios through EOF remain byte exact,
SHA-256 `348e1ff4ef98b45adbc63fd61bf9117f94f2adb429c6621ee629f78f3a2d9d52`.

A fresh first console and both metadata files were independently checked; later
profiles use only the normal same-invocation seed. Three containers run at once:
H2 320 MiB/0.5 CPU, Framework 768 MiB/1 CPU and PostgreSQL 128 MiB/0.2 CPU. Swap
limits equal RAM, published ports bind to loopback and no privileged container
or named volume is used. All memory/process-limit counters remain zero. All
**24 final independent cleanup queries** pass for exact IDs, labels and global
inventory. Earlier native/failed attempts add 62 passing cleanup queries. Docker
is empty after qualification.

## Concerns

Earlier failures remain separate from current qualification. A native-only
Compose invocation first included an incomplete Framework service; it stopped
before creating a container. The first owner run stopped at 9 cases/7 failures
and one outside error: four exact commands and one real Bash session worked,
but original classification, permission handling and cleanup failed. Two of
those assertions also used incorrect expected AutoCheck text.

The first repaired three-version replay ran all 42 cases with seven failures,
while all 18 commands and 12 complete session lifecycles worked. Native H2
backoff grew from about 0.39 to 4.18 seconds, exceeding the test's three-second
receive bound. A separate real-provider control proved that valid JDBC logins
between independent bad attempts keep responses below 0.51 seconds without
changing security settings. The final cases use that reset. A transient Docker
observer process is excluded only for exact UID 0, parent PID 0 and command
`runc init`; raw process observations remain recorded. The final source follow-up
removes generated SQL from operator errors instead of weakening the shared
unexpected-exception check.

Ubuntu apt repositories are not snapshot locked; installed tool versions and
hashes are recorded. Five missing package doc/man files match the image's
actual dpkg exclusion rules. No binary verification difference is admitted. Package versions, active
JAR and tool hashes, engine identity and canary data remain unchanged across
native phases. This scope is Linux/amd64, Java 8, the pinned H2 releases and
explicit policies; it does not establish every JDK/H2 pairing, HTTPS, proxy,
Windows, external JDBC backend or command payload/encoder combination.

Immutable evidence under `~/.codex/reports/` retains original sources, actual
requests/responses, before/after host checks and complete failed/qualified runs:

- `h2-console-source-fix-20261114T004655Z`: 101 entries; manifest
  `0d3400611290ea17b6f53ad2c81f517b3cbb2121da13dad128aab3b6cd1cb046`.
- `h2-console-error-output-followup-20261114T010206Z`: 44 entries; manifest
  `fc0cfd60d3ee222531f98be25c6624d416e85aea5f52185cdeefea5ca49ea83f`.
- `h2-console-functional-baseline-20261114`: 185 entries / 48 inputs; manifest
  `6e5bda26ecbe79f77c2d7cb500bac60568c5b20561c1c962e5436b1c16d88410`.
- `h2-console-corrected-functional-20261114`: 484 entries / 61 inputs; manifest
  `c7dfce567432bda5e7aa788e1fc05e19b55d11833f6742e0abc0db340e34a6ef`.
- `h2-console-qualified-20261114`: **527 individually rehashed entries / 61 inputs**;
  manifest `0dc47bb842a016ce20ec3b7485e9a1eb6181a17e8f08ed4ba1f5cb9fa48915aa`.

Final module SHA-256:
`53db8022496db8f0e8b681ff56db17dc63bd9a7699e6e1715bc97c5aedf0bc59`.
AI tooling prepared the lab, tests, report and isolated source repairs. Shared
Framework libraries are unchanged.

## Suggestions

The covered H2 paths have no remaining functional failure. Continue the broader
module inventory and its documented deferrals. The pre-existing Druid JS,
FreeSWITCH credential concurrency, Superset owner and WordPress administrator
investigations are separate work. No pull request was created.
