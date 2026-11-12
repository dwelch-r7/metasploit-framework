# UniFi Log4Shell verification — 2026-11-12

## Summary

`exploit/multi/http/ubiquiti_unifi_log4shell` is qualified for its Unix target
on the two pinned Linux controller images below: **16 examples, 36 public module
calls, zero failures, pending cases or outside-example errors**. The affected
controller provides four verified Bash sessions and four exact command
executions. The control provides neither. Windows, macOS, lower affected releases
and other image rebuilds remain unqualified. The campaign reaches **216 qualified
modules, 208 profiles and 2,150 functional examples**. Registration covers 218
sources; 286 documented container hints remain pending and no review is stale.

The production module, BeanFactory helper and module guide are unchanged,
including human Scenarios. The module SHA-256 is
`3cfbeacd6c44942efe79fe0dd340d1d0f5e3496cbcbfc780b1be34ffb1a7a910`.
The tested commit is `6b9c1c815fda4e942e0b6ca00467042e84ec3ba2`.

| Profile | Actual controller / Log4j | Examples / failures | Sessions | RSpec duration |
|---|---|---|---|---|
| unifi_6_5_53 | 6.5.53 / 2.13.3 | 8 / 0 | 4 | 167.962 s |
| unifi_6_5_54 | 6.5.54 / 2.15.0 | 8 / 0 | 0 | 110.716 s |

The final serial invocation is `20261112T163414-40c0c2`. Each profile pins 79
current inputs, 81 distinct across the matrix. The manager and independent
observer exit zero. The first console has an independently observed cold prompt,
BOOT and two fresh metadata snapshots. The second uses only the verified seed
from that same invocation.

## What looks good

[The reusable target guide](unifi_log4shell/README.md) and `vendor.json` record
image digests, maintainer source revisions and actual shipped JAR/class hashes.
These are genuine UniFi packages with OpenJDK 8u292, MongoDB 3.6.3 and Tomcat
8.5.56. A source-built passive Java agent records the running JVM and the code
sources of Log4j's lookup, Tomcat's BeanFactory/ResourceRef and ELProcessor. It
returns no transformed class bytes and enables no JNDI property. All observed
loaded bytes match the independently inspected vendor images.

Native prerequisites run before any owning module call. The real local setup
wizard is completed through its shipped API, including `set-installed`. Valid
login, logout, wrong-password refusal, anonymous account-access refusal, normal
management UI and one disposable local account are independently checked. The
JNDI request uses no cookie and invalid credentials.

A separate Python LDAP responder first observes lookups, then serves an ordinary
Java-serialized ResourceRef built using the target's own Java/Tomcat classes.
The benign command writes an exact marker containing the application's PID.
The affected controller performs both lookup and command execution; the control
does neither. Marker ownership, JVM kernel birth identity, loaded class hashes,
account state and the oracle's original process termination are verified. Proof
serialization and captures stay private; all added Java code has included source.

Functional cases repeat real checks, missing application paths, an unreachable
LDAP callback, exact generic commands with AutoCheck enabled/disabled, and Bash
sessions with AutoCheck enabled/disabled. A check on the same selected module
after command execution must not replay the command. An incompatible Linux fetch
adapter is explicitly refused twice per profile, before a handler or session
starts. No fetched Meterpreter execution is claimed.

Each actual session performs public RPC/file proof and a fresh response before
shutdown. Native ownership, peer identity, PID birth, database session identity,
child termination, closed SQL records and absent active callback sockets are
checked. Four marker files are removed after command execution and four after
session proof. The controller's JVM and account state remain stable. SQL checks
distinguish explicit-check, AutoCheck and session-origin vulnerability records,
including the actual target, port and CVE reference.

Cleanup is checked before recovery. No fallback cleanup journal is created.
All 32 normal harness bulk reset commands follow independently verified empty
session/job vectors; they close no active object. Sixteen final parent cleanup
queries pass. The separate fully configured native runs have sixteen additional
passing parent queries. Actual mounts contain no anonymous volumes. Docker is
empty after teardown.

Only three containers run at once, capped at **1,536 MiB, 1.8 CPUs and 512 tasks**:
controller 768 MiB / 0.6 CPU / 192 tasks, Framework 640 MiB / 1 CPU / 256 tasks,
and PostgreSQL 128 MiB / 0.2 CPU / 64 tasks. Memory and swap limits match; no
container is privileged. Native/final checks show zero OOM or PID-limit events.
The controller uses bounded JVM memory and the image's supported Mongo no-journal
setting. Only random loopback HTTPS is published. State is disposable.

Strict RuboCop reports no offenses; the tagged dry run selects exactly eight
cases. No full RSpec suite was run.

## Concerns

The control ships Log4j 2.15.0. It is a control for this CVE-2021-44228/module path,
not a claim that it fixes later Log4j vulnerabilities. The lab intentionally runs
the vendor application's root mode; other privilege/configuration combinations
need separate proof. No physical devices, cloud account or wireless network are
configured. Three capped containers still require a genuine Java/Mongo startup.

Earlier failures were investigated and preserved as setup/test faults. Docker's
copy operation could not retrieve a file on this target's tmpfs; an exec stream
plus an independent hash replaced it. An internal Compose network failed to
publish its HTTPS port on this engine, so the lab uses a normal temporary bridge
with a loopback-only published port. Initial native proof predates the final
wizard step and is retained separately from the fully configured runs.

The first functional expectations incorrectly assumed that explicit checks wrote
no vulnerability row and that AutoCheck/session reporting shared one row. Real
captures and unchanged reporting sources established their separate origins.
The next attempt selected a Linux fetch adapter outside the declared Unix target;
Framework correctly refused it. The final suite tests that compatibility refusal
explicitly. No production module defect was established by these failures.

Existing Druid, Superset RCE-owner and WordPress-admin exclusions remain unchanged.
Published CI belongs to its exact commit and is recorded separately. No PR was
created.

## Suggestions

Run the serial command in [the target guide](unifi_log4shell/README.md). Keep native
setup, loaded code identity and cleanup proof before accepting a module verdict.
Preserve the already qualified shared Log4Shell targets and human Scenarios.

Next, evaluate NetAlertX file collection. Read-only review has pinned its 24.9.12
and 24.10.12 source tags and observed the added endpoint authentication guard.
No NetAlertX image has been pulled, target started or module verdict assigned.
Validate configured authentication and native file access first; isolate its
network discovery services from the file-read test.

Private immutable evidence:
`/Users/dwelch/.codex/reports/unifi-log4shell-verified-20261112` contains 450 manifest
entries and 81 distinct input files. Manifest SHA-256:
`e761df751fc3e1bbe71899284106553177db172cecfcb6c81dfac05df5a3d72c`.
Every copied file's hash, read-only mode and link count was independently checked.
Separate immutable bundles retain both functional fixture failures and their
exact inputs. Captures contain transient lab addresses and stay private.
