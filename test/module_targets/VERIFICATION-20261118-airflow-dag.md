# Native Apache Airflow DAG execution, 2026-11-18

Six real vendor profiles pass **38/0**, with zero pending or outside errors.
One owner and six profiles advance the cumulative record to **302 runtime
owners in covered paths, 620 qualified profiles and 4,343 historical functional
cases**. The broader campaign remains active; no PR is created.
[The common guide](airflow_dag/README.md) provides setup and guarded commands.

## Actual targets and covered paths

Official pinned Apache Airflow 1.10.10 and 1.10.11 Linux amd64 images run as UID
50000 with Python 3.6.10 and 3.6.11 respectively. The vendor password wrapper
Flask-Bcrypt 0.7.1 installs offline from a checksum-verified source archive, using
existing image dependencies; no host or Framework dependencies are installed.
The real webserver, SQLite metadata database and SequentialExecutor scheduler
share one capped application container. PostgreSQL separately stores Framework
reports. Only the selected stock example DAG is deployed, with the vendor
source checksum verified. The API triggers runs of an existing DAG; it cannot
supply a missing DAG source file.

| Profile | Cases | Main distinction |
| --- | ---: | --- |
| `airflow_dag` | 13 | Stock 1.10.10, four command/session delivery families |
| `airflow_dag_fixed` | 4 | Full fixed 1.10.11, including forced nonexecution |
| `airflow_dag_denied` | 4 | Native `deny_all` API backend, working authenticated UI |
| `airflow_dag_missing` | 4 | Empty configured DAG directory, working UI/API |
| `airflow_dag_patched` | 4 | Unmodified official fixed DAG backported to 1.10.10 |
| `airflow_dag_prefix` | 9 | Native `/airflow` mount, command and two session families |

The API is explicitly open except in the denied profile. In particular, the
fixed-release profile deliberately keeps API access open to isolate the DAG
repair; it does not claim coverage of all 1.10.11 authentication defaults.
Native controls verify valid/invalid UI logins, original/deployed DAG hashes,
configuration, scheduler heartbeat, real ordinary runs and injection contrasts.
Before/after gates preserve selected users, DAG state and configuration, and
reset their concrete runs through the actual ORM. Fixed and backported DAGs
complete tasks while the injected command proof remains absent.

## Confirmed defects and source repairs

On genuine 1.10.10 with the native denied API, the original owner returns Appears
even though all three prerequisite helpers return Safe. It discards their
results and continues to unpause after failures. The isolated repair propagates
reason-bearing prerequisite verdicts in order, handles malformed task documents
as Unknown and retains expected transport exceptions for developer diagnosis.
Original focused coverage fails 29 of 37 cases; the repair passes all 37.
Malformed transport boundaries are explicitly synthetic unit cases, distinct
from the real denied/missing/backported target controls.

A real AutoCheck-disabled Meterpreter repeat starts with the DAG paused after
fixture reset. The old exploit creates a run whose task stays unqueued and
then times out. This exposes the assumption that check initialized execution
state. A second isolated repair unpauses on every exploit invocation and aborts
with the helper reason if that fails. Before/after focused results are 45/7 and
**45/0**; parent replay of all 45 also passes. The functional test retains an
explicit paused precondition rather than pre-unpausing to conceal the failure.

Two earlier fixture failures remain preserved: the historical image entrypoint
interpreted `bash` as an Airflow subcommand until the fixture selected the
image's normal dumb-init launcher; and an incorrect reporting oracle expected
one vulnerability row. Actual AutoCheck uses the module fullname while session
inference uses its display Name. The corrected oracle requires both names with
AutoCheck enabled and the session finding alone when it is disabled. Native
rows and the two producing Framework code paths establish those expectations.
Interrupted functional attempts are not complete RSpec verdicts or qualified
profiles; their original inputs, console bytes and cleanup remain sealed.

## Final native functional evidence

Run `20261118T212117-0ae5a6` retains **81 unchanged distinct declared inputs**,
50 public check/exploit calls, 569 owner trace events, 175 owner HTTP responses
and 239 independent native HTTP controls. Twelve native ordinary/injection runs
finish successfully across the relevant profiles. Genuine default command
Python Meterpreter, Python shell, Bash shell and Linux HTTP-fetch Meterpreter
sessions execute remote proof operations as UID 50000. All twelve lifecycles
verify persisted session/vulnerability records and CVE references, proof-file
removal, closed sockets and remote process exit. Repeats retain the selected
console module with AutoCheck disabled; all four root families and both prefix
families start their repeat with the DAG explicitly paused. Native state resets
permit subsequent execution. Explicit missing DAG paths and unused ports retain
reason-bearing refusals/Unknown results.

All **200 memory/PID event captures are zero**. The final replay independently
confirms removal of 30 Docker objects; all **55 distinct objects** created by
this cohort's probes and attempts are independently absent. At most two capped
containers run: application 1 CPU/1024 MiB/128 PIDs, reporting 0.25 CPU/384 MiB/
128 PIDs. Completed stacks are removed immediately. Remove only task-created
containers left unused for over an hour; unrelated initial containers are
preserved. The final task namespace is empty.

Changed test Ruby has no lint offenses. Whole-owner RuboCop and msftidy retain
only the identical pre-existing default-payload offense at line 48. Module-doc
tidy passes, and all 4,819 bytes of the original human Scenarios are unchanged.
No full local RSpec suite was run. Local evidence does not establish fork CI
checkout or execution.

## Scope and review

Qualified scope is these Linux amd64 releases, legacy password-authenticated UI,
SQLite/SequentialExecutor, the recorded API configurations, root/prefix routes
and named payload families. RBAC/other authentication backends, other versions,
executors/databases, TLS, architectures and broader custom DAGs remain untested.
The exploit unpauses the DAG and leaves run/task/log metadata for the operator;
selected metadata/proof/session removal and restoring pause are explicit fixture
cleanup, not automatic exploit cleanup.

Summary: the source fixes and genuine targets now cover both detected defects.
What looks good: independent native prerequisites, strict paused repeats, real
session/reporting/cleanup evidence and current source hashes all agree.
Concerns: the inherited lint offense and the stated coverage/CI limits remain.
Suggestions: continue the static queue and investigate other configurations only
with their own native controls. Registration alone is not qualification.

## Sealed evidence

- Final functional replay: `airflow-dag-functional-20261118T212115`, 542 files;
  `c6e7652522edb3b0d039d2aeb03fe85ec0572c94cab036946d67226684a9afc1`.
- Prerequisite repair: `airflow-check-fix-20261118T205642`, 42 files;
  `6b5d8cfa8bd486b2facd55da6e392a59f93a7e8b54c3b54d1dc3ad82a4d015b8`.
- Execution initialization repair: `airflow-unpause-fix-20261118T211939`, 30 files;
  `91be90d68ab64280f54fcab3124a36f76f43ec32439287ca83d2f53d1b5a35e0`.
- Initial reporting-oracle attempt: 130 files;
  `0bd5111bc0843d37acb6822172f8d9fd0337f67f0b644ab0a7c0da3705e22f59`.
- Paused-DAG failure: 136 files;
  `44b54bb532de52a54724beb64c512332dc89764ac3b92b87df5602d0958104c6`.

Capsules outside Git retain original inputs, actual HTTP/database/console bytes,
resource events and owned-object teardown. Compose files, fixture sources,
functional/focused specs and guides live in Framework. Final owning source SHA256:
`110542fd6648b531e1e2a008097e850f4a6c932adff9e411cad213a3a9e44acd`.

The static queue has 5,179 source files, 4,292 pending
selectable candidates, 221 pending documented container hints
and 0 stale reviews; hints do not establish feasibility.
