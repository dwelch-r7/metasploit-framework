# Native MySQL file enumeration, 2026-11-18

The repaired `auxiliary/scanner/mysql/mysql_file_enum` passes **33/0** across
three genuine server configurations. Both existing schema profiles also pass
**12/0** after sharing their identifier helper. All **45 cases** have zero pending
cases and zero errors outside examples. This adds one runtime owner, three
profiles and 33 cases: campaign totals become **298 runtime owners in covered
paths, 607 qualified profiles and 4,247 historical functional cases**. The schema
regression cases are not counted twice. The broader campaign remains active.

| Profile | Genuine target | Cases / failures |
| --- | --- | --- |
| `mysql_file_enum` | MySQL 8.0.36 | 11 / 0 |
| `mysql_file_enum_mariadb` | MariaDB 11.2.2 | 11 / 0 |
| `mysql_file_enum_nobackslash` | MySQL 8.0.36 with `NO_BACKSLASH_ESCAPES` | 11 / 0 |
| `mysql_schema`, `mysql_schema_mariadb` | Both prior schema targets | 12 / 0 |

The [target guide](mysql_file_enum/README.md) provides the serial namespaced
command. Official images are pinned to digests and reuse the existing schema-lab
services. Two containers run at once: app limits are 640 MiB for MySQL or 512 MiB
for MariaDB, with 384 MiB for the reporting database; CPU limits are 1/0.25 and
128 PIDs each. Ports are ephemeral loopback bindings. Each completed project is
removed immediately. During this campaign, unused task-owned containers up over
one hour are removed; unrelated containers and cached images are preserved.
No PR is created.

## Native controls and observed behavior

Vendor clients independently create and load numeric, nonnumeric, out-of-range,
empty and quoted filenames, inspect directories and protected/missing paths, and
contrast SQL FILE permission with filesystem permission and `secure_file_priv`.
They prove quoted database/table names by real CREATE/LOAD/SELECT/DROP operations.
Native before/after gates validate the selected release/mode, user/plugin/table/
row snapshots, file contents and POSIX ownership/modes. No parser responses or
server operations are stubbed. The native prerequisites follow the official
[LOAD DATA requirements](https://dev.mysql.com/doc/refman/8.0/en/load-data.html).

Aggregate `20261118T160319-ca6c33` records 42 actual file-collector calls and 20 schema calls,
with 353 owning-method trace events and seven genuine MySQL session lifecycles.
Loaded owner hashes match the declared source. Existing-session tests configure
an unused target port and retain the same client identity/current user. The file
collector selects its configured database with USE; that context change is
explicitly expected. Borrowed clients remain usable through repeats, stay at one
server connection while borrowed and settle to zero after closure. Standalone
calls recover to zero.

Actual Framework notes identify files/directories, retain the correct file-data
key and endpoint, and stay unique on repeats. Permission failures produce no
false positive or false absence claim. Wrong credentials and an inaccessible
database produce no filesystem notes or temporary table. Ordinary temporary
tables are removed. The documented existing-table path retains the table and
loads the expected rows on both executions, with an explicit reset between runs.
The file collector writes notes, not file loot; standalone note-created service
records still have an unnamed service label, which is retained as a legacy limit.

The schema regression produces 18 actual YAML files that match native ordered
metadata without row contents. Named service association, note uniqueness,
privilege visibility and display modes remain correct on both releases.

## Confirmed repairs and setup separation

The same six edge cases fail in each unchanged-owner configuration while native
before/after gates pass: quoted database/table and path strings are interpolated
as SQL; an out-of-range numeric file is labelled absent; the nonnumeric-file note
uses a directory key; and broad server-error handling turns filesystem/SQL
permission denials into absence claims. Ordinary, session, existing-table and
rejection controls pass before the repair.

A separate source worktree adds a shared, typed MYSQL identifier helper and keeps
the schema module's private visibility. The file collector quotes each identifier
and respects the actual per-run SQL mode when quoting literal strings, handles
the real range error as file evidence, uses the existing file-note shape, and
reports uncertain server errors with their cause. It guards nullable catalog/mode
results. The [MySQL string-literal rules](https://dev.mysql.com/doc/refman/8.0/en/string-literals.html)
explain why mode-blind client escaping cannot cover both modes.

The identical focused file baseline goes **13/10 to 13/0**. Three added mode-refresh
and nullable-query controls pass **16/0**; shared-helper 5/0 and schema 13/0 bring
the final focused total to **34/0**. Synthetic unit inputs are labelled as such.
Six syntax checks and both module tidy checks pass. There are zero new lint
offenses; 130 legacy offenses remain across the library and two modules. New
acceptance Ruby and Bash checks are clean; no full local suite is run.
The source inventory has 5,179 entries, 4,296 pending selectable candidates and
223 pending documented container hints, with zero stale source reviews.

Initial native error estimates and one overly specific nonexistent-database
wording assertion are retained as harness errors. MariaDB's first attempt stops
before the collector because its image lacks the configured secure-file directory;
a minimal container-only wrapper now creates it before the genuine vendor
entrypoint validates configuration. These setup failures are not module verdicts.
The baseline/candidate input comparison records all differences, including one
inactive optional mode assertion in the default profile and already-published
schema-guide prose. Seeds and existing case assertions remain unchanged.

## Evidence and limits

All 40 memory/PID event captures are zero. Independent post-run inspection proves
all 30 recorded containers, networks and volumes absent, with zero task containers
left and zero unrelated removals. Capsule
`mysql-file-enum-functional-20261118T160319-ca6c33` contains 324 files and 58
unchanged declared final-run inputs. Manifest SHA256:
`f236f257f40e3b0b742057f5383a88fa34a2d7bc4dd5bcf6bfb3520743e19940`.
The strict MariaDB/mode failure baseline manifest is
`c5e05d56081c06c008dcb69cd748c31b9f7ee02734874326d614fc23d99a0024`;
the separate repair-check capsule manifest is
`65b3bca815129f81b9eee91af4460e5f18e7d2ebab26398a38d0add016c26bd5`.
Guides/results are updated after sealing. No human Scenarios are invented.

Other releases, Unicode/backslash filenames, Windows/filesystem types, transport
or authentication variants, concurrent session-mode changes/DDL and interrupted
local file reads remain unqualified. Generic server failures retain uncertainty
and their cause instead of inventing an existence result. Existing-table row
changes are intentional documented behavior; this does not claim recovery from
every possible process interruption.

**Summary:** All three covered file-collector configurations and both schema
regressions pass. **What looks good:** independent native contrasts, real sessions,
typed persisted notes, exact metadata, strict repeats and selected recovery.
**Concerns:** stated limits, the legacy unnamed standalone service label and
legacy lint remain. **Suggestions:** retain the native controls when extending
versions, SQL modes or file types, and qualify directory-write testing separately.
