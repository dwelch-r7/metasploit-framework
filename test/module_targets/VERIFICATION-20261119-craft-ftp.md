# Native Craft FTP template verification — 2026-11-19

The final three-profile replay passes **10/0**, adding one runtime owner and three
qualified profiles in the covered paths. Campaign totals become **309 runtime
owners, 638 qualified profiles and 4,609 historical functional cases**. Four
actual Meterpreter sessions are used and closed. The broader goal remains active;
no PR is created.

| Profile | Cases/failures | Used/closed owner sessions | Native outcome |
| --- | --- | --- | --- |
| Craft 4.13.0, PHP argument parsing enabled | 6/0 | 4 | FTP reads, Twig rendering and command execution work |
| Craft 4.13.0, argument parsing disabled | 2/0 | 0 | FTP reads work; injected template execution is refused |
| Craft 4.13.2, argument parsing enabled | 2/0 | 0 | FTP reads work; fixed bootstrap refuses injected paths |

Reproduce with the [maintained guide](craftcms_ftp/README.md). The final replay is
`20261119T104633-a345d6`; it has no pending cases or errors outside examples.
All 127 declared input digests remain unchanged. These new counts exclude every
failed prototype and earlier command-only calibration matrix.

## Genuine targets and independent controls

The shared Craft Dockerfile installs pinned application releases and Composer
locks. All 99 non-CMS package records are identical between the vulnerable/fixed
locks. The official base, historical starter, CMS references and critical source
hashes are recorded in [release provenance](craftcms_ftp/releases.json). Actual
nginx, PHP-FPM, Craft, Twig and PostgreSQL perform the work. The PHP setting is
configured through the supported FPM pool flag.

Seventeen native application controls pass before and after every profile:
**102 checks** in total. They cover ordinary/database-backed rendering, genuine
administrator login, rejected credentials, installed source bytes, stable master
processes and preserved application state. All seventeen recorded snapshots match
their profile's baseline, including the pre-existing harmless upload.

A real auxiliary FTP service first supplies known bytes to PHP's actual wrapper.
Native Twig arithmetic and a command-created file calibrate the vulnerability
separately from the owner. Protected profiles retain working FTP reads while
refusing those execution controls. The owner's generic command then creates the
expected file under UID 82 on the vulnerable image and is refused elsewhere.

Before fetch owners, native curl/wget transfers execute independently assembled
x86/x64 ELF files with exact hashes, UID 82 and exit status 42. Owner cases use
x86 inline Meterpreter over HTTP fetch and x64 staged Meterpreter over wget fetch.
Both families repeat with the same selected console module and AutoCheck disabled;
passive traces confirm checks run only on the first executions.

Every session writes through its filesystem API, closes the file channel, matches
an independent native PID/UID/executable hash and live TCP connection, and has
correct owner/payload/workspace metadata. Graceful shutdown closes the process,
connection and persisted database row. A separate raw SQL observer verifies all
four closed owner rows and zero native session rows. Protected profiles have no
session or vulnerability rows. The vulnerable profile's session workspaces carry
CVE-2024-56145 reporting references.

## Confirmed check repair

An independent raw socket connection to the app's closed port returns
`Errno::ECONNREFUSED`. The original real module receives no HTTP response but
returns `Safe`, claiming the target is not vulnerable. The focused repair returns
a reason-bearing `Unknown` for missing responses and expected transport errors.
Genuine warning-body and healthy-response classifications are preserved.

Identical focused source regressions change **14/8 failures to 14/0**. HTTP is
stubbed only in those focused specs; the native refused-port replay independently
confirms the final `Unknown` result. The parent's normal RSpec invocation passes
21/0: fourteen target cases plus seven automatically loaded datastore-formatting
support cases. Syntax, RuboCop, module msftidy and the module-document checker all
pass, with no inherited or new offenses. The original 6,948-byte human Scenarios
suffix remains byte-identical. No host/Framework dependency is installed and the
full RSpec suite is not run.

## Retained setup and harness investigations

The host route fails independent passive FTP transfer controls. The Framework
listener therefore runs inside the isolated Compose network. An inherited
loopback LHOST also takes precedence over explicit SRVHOST in the shared helper;
the fixture configures LHOST and verifies the actual advertised address.

The genuine 4.13.1 installer hits the documented upstream CLI bootstrap regression.
The older 4.4.14 bootstrap refuses the remote template root despite working native
FTP reads. These remain setup/version investigations; application code is not
patched to force either environment to pass.

Earlier prototypes retain their failures: JSON-to-Twig redirection escaping,
abstract-class observer lookup, premature passive-job assertions and multiline
console transport. Each is classified separately from the confirmed source bug.
An earlier six-minute bound interrupts final verification after four used/closed
sessions; that pilot remains unqualified. Filtering observer methods before path
work and allowing a bounded eight-minute positive suite produces a complete final
vulnerable profile in 179 seconds, including setup and cleanup.

Two unrelated initial container IDs disappear during one failed pilot; their
removal cause is unverified. That receipt does not claim all initial containers
remain present. The final qualifying matrix independently preserves every one of
its initial unrelated container IDs.

## Ownership, resources and evidence

Profiles run serially with at most three task-labelled containers. Craft uses
0.75 CPU/768 MiB/128 PIDs, PostgreSQL 0.25 CPU/384 MiB/128 PIDs, and Framework
1 CPU/640 MiB/128 PIDs. All **108 resource-event captures** contain zero events.
All **18 observed owned Docker objects** are independently absent afterward:
nine containers, six networks and three volumes. The namespace finishes empty.
Completed stacks are removed immediately; unused task-created containers older
than one hour are removed within the recorded ownership scope.

The final evidence is sealed as `craftcms-functional-20261119T104632`, 412 manifest entries,
with SHA256 manifest
`1f95de43912abdcf97ddbd323116e5681028ca4ae02625708603e83830221152`.
The source repair capsule is `craftftp-check-confirmed-fix-20261119T104205`,
manifest `fc7c2a28a170a62b19fded2890c84ed12d20744bb83c6347c4a523c1769ea767`.
Earlier command/configuration calibration is sealed as
`craftcms-functional-20261119T102131`, manifest
`ed03efc20dc49a740cc0ff7ae0767a5d65dfa1a22d897f289f5d6a4760859c16`.

## Self-review

**Summary:** Genuine targets, native prerequisites and a focused check repair
qualify the declared Linux command/fetch paths.

**What looks good:** Independent FTP/ELF/SQL evidence, four used/closed sessions,
configuration/release contrasts, repeat execution and scoped cleanup all pass.

**Concerns:** Other Craft branches, Unix platforms, HTTPS deployments and payload
families remain outside this qualification. Earlier Craft PHP runtime limits are
unchanged. CI qualification is separate from these local results.

**Suggestions:** Continue the broader module campaign; retain the failed/version
investigations when adding future profiles.
