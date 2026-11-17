# Rsync credentials through shell sessions, 2026-11-17

Qualified `post/multi/gather/rsyncd_creds` in one profile with **five passing
functional cases in one aggregate with exit 0**. Cumulative coverage reaches
**284 runtime owners in covered paths, 578 qualified profiles and 4,012
historical functional cases**. The broader campaign remains active. No PR is
created.

## Reproduction and target controls

Run the command in the [target guide](rsync_creds/README.md). The profile reuses
the existing digest-pinned Ubuntu 22.04 rsync image and pinned PostgreSQL 16
reporting service. Its actual rsync package is `3.2.7-0ubuntu0.22.04.7` and Python
package is `3.10.6-1~22.04.1`. Both actual container image IDs report Linux/amd64.
The target runs an ordinary rsync daemon with a protected share and a real
root-owned mode-0600 secrets file. No parser, session transport, daemon response
or persistence API is replaced in the functional suite.

Native controls run before and after owning calls. Across those phases, eight
real rsync client authentication controls accept the correct password and reject
the wrong one, from root and ordinary-user processes. Two authenticated downloads
match the exact proof file. Native UID and file-permission checks establish which
configuration and secrets each user can read. Global and two root-home
configuration files contain the same bytes as the running daemon's configuration.
Selected file hashes/owners/modes and the daemon PID match before and after.

An ordinary PostgreSQL role begins with an empty schema; Framework creates and
uses its real schema. A native token callback validates the Docker-to-host route
before Framework listeners start. Framework generates actual ELF shell payloads,
the target executes them, and real handler events and database session records
establish each session. Independent target-side marker ownership proves four
root shells and one UID-1001 shell. Payload delivery is a session prerequisite,
not an rsync exploit result. The owner declares only shell sessions.

## Confirmed defect and owner-only comparison

The original owner passes a target path to `Rex::Parser::Ini.new`. That
constructor reads the Framework host using `IO.readlines` and suppresses missing
file errors. The target-only `/etc/rsyncd.conf` is absent on the host, so the
owner silently finds no shares despite its own session file API being able to
read both the target configuration and secret.

The clean original run `20261117T212654-5271e6` has three cases, two failures,
zero pending/outside errors and four owning calls. Both root cases return no
credentials; the unreadable-secret negative passes. Native prerequisites,
session reads, process/artifact recovery, closed database sessions and Compose
teardown all pass. This establishes the owner defect separately from setup.

The repair reads the configuration through `read_file`, parses its returned
bytes with the real `Ini.from_s`, and skips nil configuration/secrets reads.
The unchanged three-case/four-call replay `20261117T213402-38140f` passes 3/0.
Its 46 declared inputs differ only in the owner; the other 45, including the
fixture, functional spec and helper, are byte-identical. The root calls persist
the expected credentials and the ordinary-user call persists none. Original
owner SHA256 is
`236555295f56155c497f1fded3fdd68913da72c23ffb68f7493b752435235621`;
repaired SHA256 is
`ccec13acc94a6604671e10e31239e7886844992820784a05a34111c3b4cad21e`.

An earlier public attempt has three failures, including a harness cleanup
timeout: an idle raw shell can exit without Framework noticing EOF. The corrected
harness first proves the remote PID absent, explicitly removes any stale session
registration and verifies database session closure. Its clean original run above
precedes the owner repair. That earlier attempt is retained and excluded from
qualification. A helper semicolon style offense was retained through the strict
source-only replay, then corrected before the final run.

The separate deterministic contracts use exact captured daemon files and the
real owner/parser. The identical final spec produces 12 examples/11 failures on
the original, then 12/0 on the repair and 12/0 again. Transport, framework/session
metadata, persistence and output are doubled there; those examples do not prove
native sessions or reporting. Initial missing-require and Ruby-3 expectation
setup mistakes are preserved separately and excluded from that comparison.

## Selected functional aggregate

Run `20261117T213822-aaef70` passes **5/0**, with no pending or outside errors and
successful teardown. Its five cases take 140.7 RSpec seconds, including session
prerequisites and recovery:

| Case | Owning calls | Expected persisted credentials |
| --- | ---: | --- |
| Target-only global configuration and same-instance repeat | 2 | One core/login pair, reused on repeat |
| Default home enumeration, including missing user files | 1 | One session-origin core/login pair |
| Ordinary user cannot read the secrets file | 1 | None; no crash |
| Missing selected daemon configuration; home search disabled | 1 | None; no fallback or crash |
| Custom home filename after missing daemon configuration | 1 | One session-origin core/login pair |

The six actual `run` calls use five typed Linux shell sessions. Direct queries
observe three unique credential cores and three corresponding logins, with exact
username/password, session origin, post reference, service/address, TCP port 873,
User access and Untried status. Attempt timestamps remain nil. Native correct
password authentication is separate from that untested-login reporting status.
Console completion alone is never treated as collection success. Repeats retain
the same module object and deduplicate the existing credential/login records.

All five remote processes terminate, Framework registrations disappear and their
database session records close. Native operator recovery removes only the
SHA-checked generated ELFs and exact marker contents. Framework sessions/jobs
finish empty. The owning module does not modify the selected target files.

## Resources, evidence and limits

One capped stack runs at a time, with at most **two work containers**, totaling
0.75 CPUs/640 MiB, equal memory/swap limits, PID limits and init. Ports bind only
to loopback. Eight memory/PID snapshots have zero OOM/limit events. The attached
database volume and both networks are individually absent after teardown; no
containers remain. Unrelated images and volumes are not pruned. The Docker
engine was observed ready after the user's restart; a changed disk cap is not
independently verified.

Changed Ruby syntax/RuboCop, owner msftidy, shell/Python syntax and resolved
Compose/input checks pass. Msftidy skips legacy-owner RuboCop automatically;
the separate scoped RuboCop run covers it explicitly. No full RSpec suite runs.
Immutable private archives retain the original failures, exact 46-input cohorts,
raw transcripts/JSON, native controls and focused-contract evidence. Preliminary
native, failed, source-only replay and unit cases are not counted again in the
five newly qualified functional cases. Publication CI is separate from these
opt-in target tests.

This qualifies the shown Linux/amd64 shell, package and configuration paths.
Other operating systems/architectures, alternate daemon ports, global INI
inheritance, other rsync configuration/credential grammar and transport loss
remain unqualified. The existing hardcoded reporting port and omitted realm key
are unchanged. The owner has no `check` method. No historical human Scenarios
are created or modified.
