# Native MySQL directory writes, 2026-11-18

The repaired `auxiliary/scanner/mysql/mysql_writable_dirs` passes **27/0** across
MySQL 8.0.36, MariaDB 11.2.2 and MySQL with `NO_BACKSLASH_ESCAPES`. The same three
file-enumeration profiles pass **33/0** after reusing the shared literal helper.
All **60 cases** have zero pending cases and zero errors outside examples. This
adds one runtime owner, three profiles and 27 cases, reaching **299 runtime owners
in covered paths, 610 qualified profiles and 4,274 historical functional cases**.
The 33 regression cases are not counted twice. The broader campaign stays active.

The [target guide](mysql_write_dirs/README.md) provides the serial namespaced
command and the intentional file-artifact/reset contract. Each writer profile
runs nine cases; each file-enumeration regression runs eleven. Official images
are pinned to digests and reuse the existing SQL/session controls. Two containers
run at once, with app/reporting limits of 640/384 MiB for MySQL or 512/384 MiB for
MariaDB, 1/0.25 CPUs and 128 PIDs each. Ports bind ephemeral loopback addresses.
Completed stacks are removed immediately, unused task containers up over one
hour are removed during the campaign, and unrelated containers are preserved.
No PR is created.

## Independent native controls

Vendor clients prove exact four-byte `test` files at ordinary, quoted and
backslash-containing paths, verify mysql ownership and the actual per-server
creation mode, then prove filename collisions refuse overwrite. Native controls
also contrast OS permission denial, missing/non-directory destinations, SQL FILE
privilege denial and the `secure_file_priv` boundary. They run before and after
module execution with unchanged selected SQL/user/table/row and filesystem
snapshots. No response handler, parser or server operation is replaced.

The first setup attempt assumed an OS error for an invalid destination; MySQL's
secure-file normalization can reject it first. The corrected gate retains the
actual vendor error and requires failure plus no destination file. MariaDB's
FILE denial is independently observed as 1045, compared with MySQL's 1227.
Both setup-only failures stop before owner calls and remain separately sealed.
These are fixture corrections, not module verdicts. Native requirements follow
[SELECT INTO DUMPFILE](https://dev.mysql.com/doc/refman/8.0/en/select-into.html).

## Actual owner behavior and confirmed repair

Unchanged default MySQL and MariaDB each fail five of nine cases; the
`NO_BACKSLASH_ESCAPES` profile fails three. Native exact-path writes and ordinary
module/session/collision/reset/authentication controls pass. The module's raw SQL
misparses quotes and interprets backslashes as escape sequences. A configured
literal backslash-b is printed intact by the module but the server creates a file
whose name contains byte `0x08`. Under the no-backslash mode, that same test writes
the correct path. This contrast separates SQL interpolation from console parsing.

A separate worktree adds a typed shared MYSQL literal quoter with a required
observed mode, plus a String/nil mode getter without hidden connection state. The
directory writer snapshots the current mode locally for each run; its direct
helper remains callable with the original argument and an optional mode keyword.
File enumeration retains its private wrapper and per-run snapshot. Neither
module mutates the server's mode or datastore. Quoting follows the official
[string-literal rules](https://dev.mysql.com/doc/refman/8.0/en/string-literals.html).

Final aggregate `20261118T164839-e88fa6` records 39 real writer calls and 42 file-enumerator
calls, six genuine MySQL sessions and 396 owning-method trace events. All 42
recorded writer file observations retain exact path, `74657374` bytes, mysql owner
and the native creation mode. This observation count includes collision/repeat
snapshots. MySQL creates mode 640 files here; MariaDB creates mode 644 files.
Real Framework notes retain their expected type/data/endpoint and stay unique.
Credential/FILE denials create no files or notes. Collisions produce no new
success claim, and explicit lab reset permits another successful run with the
same active console configuration.

The writer intentionally leaves its four-byte files, as its description states.
The harness records actual files, including wrong escaped names in baselines,
before removing only the test prefix in newly created task-owned lab directories.
This is explicit test-state reset, not a claim of automatic module cleanup.
Borrowed writer sessions retain connection identity, current user and database;
file enumeration's documented USE context change remains expected. Borrowed
clients remain usable, stay at one connection while borrowed and settle to zero
after closure. Standalone calls recover to zero.

## Focused checks and evidence

The corrected focused baseline has library17/12 and writer17/10, while existing
file16/0 and schema13/0 controls pass. The candidate passes **63/0**. Earlier unit
session-adapter errors are retained as harness failures. Synthetic query/error
inputs are labelled; actual files/session behavior comes from the native replay.
The twelve library failures are new API expectations against the old code,
not claims of pre-existing defects in those previously absent methods.
Six syntax and both module tidy checks pass. There are no new lint offenses;
133 legacy offenses remain across the library and two modules. New acceptance
Ruby/Bash checks are clean. No full local suite is run.
The inventory contains 5,179 sources, 4,295 pending selectable candidates and
223 pending documented container hints, with zero stale source reviews.

The input comparison records source changes, the two exact vendor-denial fixture
edits that leave MySQL's same 1227 check in place, and previously published guide
prose. Existing case assertions and exact-path/byte expectations remain enabled.
All 48 memory/PID event captures are zero. Independent post-run inspection proves
all 36 recorded containers, networks and volumes absent, with zero task containers
remaining and zero unrelated removals.

Immutable capsule `mysql-write-functional-20261118T164839-e88fa6` contains 395 files
and 67 unchanged final-run declared inputs. Manifest SHA256:
`e8b76253bf7baf878af8657bf940fac745fd3a526ecc3380a82b038d29476051`.
Default MySQL, corrected MariaDB and mode-contrast baseline manifests are
`56af2fcbe024afff90e10d56eb57f6eb3e1ce1c86e71184c037f892f04e47198`,
`288a0f821efaf6dd16b9bff5d0e7582c8216d9eb1cc605daacd18b34390a63b1` and
`160891b288f17ba57c44ed3f169de9e4d706c9b4e19f42f8b8bc0fbc4aa6cf66`.
The separate repair-check capsule manifest is
`160e8ee8138fc1e852ffe3e7f32600da2d9d3d40f042814a7df8bb556f6eba3b`.
Guides/results are updated after sealing; no human Scenarios are invented.

Other releases, Unicode names, Windows/other filesystems, ACL/symlink variants,
other transports/authentication and concurrent mode/filesystem changes remain
unqualified. Standalone note-created service labels remain unnamed. These tests
do not promise rollback of intentional artifacts after process interruption.

**Summary:** Three writer configurations and all file-enumeration regressions
pass. **What looks good:** actual bytes/paths/permissions, mode contrast, real
sessions, typed notes, collisions, resets and connection/resource recovery.
**Concerns:** stated limits and legacy lint/service labels remain.
**Suggestions:** reuse the native gates for other versions or filesystem types;
keep intentional artifacts and explicit lab reset clearly distinguished.
