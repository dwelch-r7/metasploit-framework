# Native MySQL schema collection, 2026-11-18

The repaired `auxiliary/scanner/mysql/mysql_schemadump` passes **12/0** on genuine
MySQL 8.0.36 and MariaDB 11.2.2. Both profiles run six cases with zero pending cases
or errors outside examples. Campaign totals become **297 runtime owners in covered
paths, 604 qualified profiles and 4,214 historical functional cases**. The broader
campaign remains active; no PR is created.

The [target guide](mysql_schema/README.md) provides one serial, namespaced command.
Pinned official servers run with a separate real Framework reporting database.
Two containers run at once: MySQL is capped at 640 MiB, MariaDB at 512 MiB, and the
reporting database at 384 MiB; app/reporting CPUs are 1/0.25 with 128 PIDs each.
They use ephemeral loopback ports. Normal teardown is immediate, and unused
task-owned containers older than one hour are eligible for cleanup. Unrelated
containers and cached images are preserved.

## Independent setup and actual collection

Native vendor clients create and inspect ordinary and empty databases, an empty
table, a view, multiple column types, spaces/hyphens, a reserved table/column name
and embedded backticks. SELECT-only accounts see either two or four application
databases; a USAGE-only account sees none. Native permission denial and fully
quoted table/column queries prove these are real server objects and grants.
Expected metadata comes from native information-schema hex fields, preserving
column ordinal positions. No response handler, parser or server implementation
is replaced.

Native gates before and after each profile confirm the exact server release,
visible metadata, privileges, unchanged schema/user/plugin/row snapshots and
connection recovery. MySQL 8's internal event-scheduler `Daemon` is recorded
separately from clients. `FLUSH PRIVILEGES` before each case clears authentication
caches; successful standalone and session cases then repeat without that reset.
An initial setup-only run incorrectly counted the server Daemon as a client and
stopped before any collector call. That failure is retained separately; correcting
the native client filter preceded module classification.

The aggregate `20261118T152945-65bb8a` records 20 real collector invocations and
158 entries into owning source methods. 4 genuine MySQL sessions are created by
the login module. Borrowed-session cases deliberately configure a closed target
port, retain the same connection identity and remain usable after both calls.
The connection count stays one while borrowed and settles to zero after session
closure; standalone calls recover to zero. Loaded source hashes and isolated
console configurations are captured.

All 18 actual YAML loot files match native database/table/ordered-column metadata
and exclude the seeded row-content sentinel. Actual Framework schema notes match
the same metadata, retain the correct named MySQL endpoint and remain unique on
repeat. Both display modes work; USAGE-only users export an empty schema, and
wrong passwords create no schema loot or notes. These are database observations,
not only console success assertions.

## Confirmed defects and repair

The unchanged owner fails three of six cases on **both** database releases:
standalone and borrowed-session enumeration parse valid unquoted identifiers as
SQL and dereference the failed query's nil result; ordinary standalone repeats
also duplicate schema notes. In the latter path, notes first create an unnamed
service, then the module creates a named one; subsequent port-only lookup can
associate identical notes with a different service.

A separate worktree repairs the same module by quoting each identifier component
and doubling embedded backticks, aborting failed catalog queries with an operation
reason, and explicitly associating notes with the named service created after
successful enumeration. Metadata shapes and helper signatures remain intact.
The quoting follows the [MySQL identifier rules](https://dev.mysql.com/doc/refman/8.0/en/identifiers.html).

The focused native-capture regression goes from **13/12 to 13/0**, with zero errors
outside examples in the valid baseline. Query-failure controls are explicitly
synthetic unit inputs. Earlier spec bootstrap mistakes are retained as harness
failures. Syntax and msftidy pass; RuboCop has zero new offenses and 16 legacy
module offenses remain. The new acceptance helper/spec and Bash checks are
clean. The static inventory contains 5,179 sources, 4,297 pending selectable
candidates and 223 pending documented container hints, with zero stale reviews.

The final acceptance matrix retains the baseline SQL seed, native gates, case
assertions, versions and resources. Its input comparison records the repaired
owner plus exactly two equivalent helper lint edits (a quote style and
`Hash#except` for the same rejected key); every other declared input is identical.
Strict duplicate-note assertions remain enabled. No module documentation or
human-authored Scenarios are fabricated.

## Evidence and remaining limits

All 16 memory/PID event captures are zero. Independent Docker inspection confirms
all 12 recorded containers, networks and volumes are absent, with zero containers
left in the task namespace and zero unrelated removals.

Immutable capsule `mysql-schema-functional-20261118T152945-65bb8a` contains 149 files
and 42 unchanged declared inputs from the final run. Its manifest SHA256 is
`9232db15b2159e4070cd50b5e685762308a92afea1c18ef9992af823d3f24d15`.
The strict two-release failure baseline capsule manifest is
`6ee0596bfef2d7f342a02bc59595b0837ebb5bc07cd41abf1313a3f50ca808fb`;
the separate repair/check capsule manifest is
`994cd5ab1ff603a0a5fb158046edcf3cd620ae7c322abc5d1a62670f62486a23`.
Guides and results are updated after sealing; runtime inputs stay recorded.

Other server versions, Unicode identifiers, TLS/socket transports, concurrent DDL,
and other authentication plugins remain unqualified. Runtime tests exercise
ordinary grants and metadata visibility; transient catalog-query errors are
covered by the focused controls rather than induced server interruption.

**Summary:** Both native profiles qualify the covered collector paths after two
confirmed repairs. **What looks good:** complete metadata/loot/note comparisons,
both declared connection paths, strict repeats, privilege contrasts and selected
recovery pass. **Concerns:** the stated version/transport/concurrency limits and
legacy lint remain. **Suggestions:** reuse the native gates when adding server
releases or authentication modes; retain exact note association and nil-query
controls.
