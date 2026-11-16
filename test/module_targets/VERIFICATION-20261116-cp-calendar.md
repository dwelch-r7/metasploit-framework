# CP Multi-View Calendar qualification, 2026-11-16

This checkpoint adds **one runtime owner, eight profiles and seventeen functional
cases**, reaching **268 runtime owners in covered paths, 467 profiles and 3,624
functional cases**. The [module](../../modules/auxiliary/scanner/http/wordpress_cp_calendar_sqli.rb)
maps to the targets through their manifests. The [lab README](cp_calendar/README.md)
contains preparation and serial guarded-runner commands. Earlier coverage stays
historical; the broader goal remains incomplete. No PR is created.

## Genuine source and native gates

Unmodified CP Multi-View Calendar **1.1.4 / 1.1.5 / 1.3.70** archives run on
pinned WordPress 6.8.3 / PHP 8.3.28 and MariaDB 11.2.2. The
[catalog](cp_calendar/releases.json) pins complete archives, installed critical
files and the actual native event-column order. The unavailable historical
official ZIPs are replaced by pinned Git mirror exports: eight selected files
per release match official historical SVN revisions 1076621 / 1101803 exactly.
The mirror wrapper is renamed to the ordinary plugin directory without editing
vendor files. The genuine vendor installer creates its four tables and default
calendar. Native bulk activation avoids the later version's wizard redirect.

The pinned 1.1.5 archive remains demonstrably injectable despite a published
fix label. The official 1.3.70 archive refuses the same well-formed SQL controls.
These results qualify exact archived bytes; the earliest fixed release and
possible historical tag changes remain unresolved. The human guide's older
setup text is preserved; use the pinned lab recipe for this qualification.

Three release probes and a used-calendar probe make 45 independent native HTTP
requests. Their 268 sealed entries are independently rehashed. A real vendor
datafeed API creates event ID 1, and its ordinary editor renders the known title
and location. These setup/native probes add no module cases.

## Confirmed public false negatives and repair

On an empty event table, the original UNION row's NULL start/end dates make
PHP 8 abort through `mySql2PhpTime` / `mktime` before rendering the location
marker. Independent rows with valid datetimes reach that marker. With genuine
event ID 1 present, the original leading `1` selects the real event before the
UNION row; even valid injected dates cannot reveal that second row. Negative
IDs with valid dates expose the injection in both states. These are separate
native diagnostics, rather than an assumption that a failed marker means Safe.

The original public console runs then reproduce both defects. The same two
profiles contain five public calls: four positive calls fail their finding
assertions, while the reserved closed-port control passes. Before/after native
positive gates, ordinary reporting setup, source/user/event snapshots and
cleanup pass. Empty-calendar target logs contain the actual original query and
PHP date error; the event fixture retains its real first event. No original
case is added to qualified coverage.

The repair uses a nonmatching negative ID and non-NULL SQL `NOW()` date values.
It preserves fourteen columns, the location marker, quote-free request values,
options, route, reporting name and references. The same five public cases then
pass, with the owner as the only changed declared input. Both corrected profiles
are retained in the final matrix. The target source is never patched.

Separate-worktree commit `f522168b771f2e13468d77202e4759fbb22b6d08` is imported as
`251fbd4198dbefeeb17ddf050d60aafcd7549b07`. The same seventeen focused unit cases
have three original failures and zero repaired failures; project-default file
invocation also passes seventeen. HTTP, UI, framework access and reporting are
explicit doubles, using native HTML excerpts with only the generated positive
marker substituted. They do not emulate SQL/PHP or add functional cases. Initial
unit runtime/load-order corrections remain preserved separately. All sixty
worker evidence entries and exact imported blobs are independently verified.

Msftidy passes before/after. Strict owner lint retains eighteen baseline offenses
with zero introduced; the new unit spec is clean. The new functional spec and
archive-preparation wrapper pass lint with zero offenses. Original/repaired owner
SHA256 values are respectively
`e3c5357441fcb0304399069ad086dd3bb3d6e303de443ee6086a274ff0e7c990` and
`1e2fd772723244b17b0e750457213dfbd089e9b94604ae9c616760ffbf6de1e8`.
The entire human guide and Scenarios remain byte-identical:
`cac612ccc013c84189d93ef89e2d1ed8a9edfe2bec5285370536f0234cec0f20`.

## Final public results

| Profile | Actual run | Cases | Public calls | Native HTTP | Deduplicated findings |
| --- | --- | ---: | ---: | ---: | ---: |
| `cp_calendar` | `20261116T192704-e55872` | 3 | 3 | 8 | 1 |
| `cp_calendar_115` | `20261116T193844-115fde` | 2 | 2 | 8 | 1 |
| `cp_calendar_absent` | `20261116T194231-151036` | 2 | 2 | 8 | 0 |
| `cp_calendar_event1` | `20261116T192828-49d195` | 2 | 2 | 9 | 1 |
| `cp_calendar_fixed` | `20261116T193959-77f664` | 2 | 2 | 8 | 0 |
| `cp_calendar_inactive` | `20261116T194117-a7f316` | 2 | 2 | 8 | 0 |
| `cp_calendar_prefix` | `20261116T193726-c67863` | 2 | 2 | 8 | 1 |
| `cp_calendar_subdirectory` | `20261116T193610-8f468f` | 2 | 2 | 8 | 1 |

All seventeen public calls pass: ten positive detections and seven negatives.
The scanner has no public check hook. Actual PostgreSQL data contains five
deduplicated, service-linked vulnerability rows and ten module-attempt rows,
with the correct endpoint, protocol, module context and EDB reference. Repeated
calls retain one finding per positive workspace. No credentials or loot are
created. The reporting role is ordinary, and each profile starts with a fresh
schema before genuine Framework migration and reporting.

The final profiles make 65 independent native HTTP
requests. Both normal public requests in every profile also appear in its
managed target access log; negatives cannot silently pass by failing to connect.
The additional closed-port case uses a reserved non-listening loopback socket.
No HTTP, SQL, reporting or loot transport is stubbed in these functional cases.
Selected source, Core users, native schema/events and configuration snapshots
match before/after; these are not complete database dumps. No target PHP fatal
error remains in any final profile. Framework jobs and sessions finish empty.

## Setup failures, inputs and cleanup

An initial native resource validator compared Compose's numeric strings with
integers and stopped before startup. An initial NULL-date positive control did
not qualify the affected target until valid datetime projections were used.
The first subdirectory profile omitted the working directory required for Core
installation under `/wordpress` and failed readiness before any module call.
That profile-only Compose change leaves the first two qualified profiles' input
sets untouched. A wrong inherited Ruby gemset also stopped before lint; selecting
the already-installed project Ruby 3.3.13 requires no dependency installation.
All failed setup/control receipts stay sealed and add no cases or module verdict.

All 655 final runtime entries are independently
rehashed. All 62 tracked consumed inputs match source/
fixture commit `91b1d43b1da2b0fe98a6f30fcdc63b6efb10fff8`; three ignored source archives match the catalog and
sealed bytes. Every final profile has exact current declared inputs, with no
compatibility exceptions. Runtime records retain their actual earlier HEAD and
working-file hashes rather than claiming checkout of a later commit.

Each serial stack has three capped containers: app 1 CPU / 512 MiB, MariaDB
0.5 CPU / 512 MiB and ordinary PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory,
PID limits are 128, init is enabled and published ports bind loopback. All
96 native OOM/PID event rows are zero. The reporting
component reuses the existing Elasticsearch PostgreSQL definition without
starting Elasticsearch. Each stack is removed before the next; all forty
attached volumes/networks are independently absent, along with every selected
project and the global container inventory. The lock is free and no host Ruby
process remains in this worktree. Two unrelated MCP service containers appearing
between probes were removed under the user's explicit policy; no unrelated
images or volumes were pruned.

Fresh inventory: 5179 source modules,
4622 candidates, 269 registered
candidates, 4327 pending candidates and
236 pending documented container hints.
All 29 source-pinned target-requirement reviews are current.
Registration and source-only review are separate from runtime qualification.

## Review

Summary: Eight genuine profiles pass all seventeen cases and clean up completely.

What looks good: Independent SQL, real vendor event creation, public failure/
repair replays, ordinary reporting and actual target access logs arbitrate results.

Concerns: Eighteen baseline lint offenses remain. Other WordPress/PHP/database
releases, authentication, TLS/IPv6 and different event schemas are unqualified.
The earliest fixing release remains unknown; historical titles still name 1.1.4.

Suggestions: Keep those version/scope limits explicit, follow actual publication
checkouts and continue the remaining module inventory. The wider goal is active.
