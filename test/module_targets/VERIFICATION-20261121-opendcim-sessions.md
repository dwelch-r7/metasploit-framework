# openDCIM Bash session lifecycle

The separate [session recipe](opendcim_sessions/README.md) qualifies **three
examples / zero failures / zero pending** and **three used/closed shell sessions**:
one independent stock-handler control, followed by two actual exploit sessions
on target 0. The existing six command/check cases retain their unchanged input
fingerprints. Production module source is unchanged in this addition. No PR is
created, and the broader module-inventory goal remains active.

## Native prerequisites and scope

The pinned official image reports openDCIM **24.01**, PHP **8.1.2-1ubuntu2.14**;
MariaDB reports **10.11.9**. The original application installer creates the
database. Apache supplies `REMOTE_USER=dcim`; no application source is patched.
Existing native controls verify real SVG rendering, stacked SQL, exact quoted
command execution and seven source fingerprints. All 145 full configuration
rows and the complete table-name registry are observed, with thirteen non-empty
LDAP values seeded to reveal accidental changes.

A separate namespaced, network-disabled image probe runs as UID 33. It verifies
the normal PATH contains Bash but neither `curl` nor `wget`. The maintained
profile repeats that tool check. Framework actually selects
`cmd/linux/http/x64/meterpreter/reverse_tcp` when this owner is first loaded;
the missing fetch tools are recorded as a target prerequisite gap. These
results qualify an explicitly selected `cmd/unix/reverse_bash` payload.

An acknowledged native TCP callback first establishes route and UID/PID identity.
The independent handler then generates the stock Bash payload. Its exact bytes
are retained and the copied script's checksum is verified before the already
generated command executes as UID 33. Successful native session use and cleanup
gate the owner case.

## Actual module behavior

The first owning run enables AutoCheck and receives the real reason-bearing
three-delay SQL injection verdict. The second disables AutoCheck and reuses the
same selected module. Both use the normal HttpClient timeout rather than the
shorter Laravel helper setting. Passive traces capture actual module source
locations, payload command bytes, SQL and HTTP activity. Distinct backup-table
names demonstrate fresh per-run state.

All three sessions execute a remote command and create a physical file containing
exactly `opendcim-session`, owned by UID 33. The shell reports its PID. The target's
process snapshot independently records its UID and birth value alongside an
established callback connection. A fresh command must still respond before
graceful remote exit. The exact PID/birth pair disappears, callback connections
close, Framework jobs/sessions empty and the original SQL reporting row acquires
a closure time. Each proof file is removed and absence checked.

Apache can add ordinary prefork workers while the foreground command occupies a
worker. Additional idle processes are accepted only when they are UID-33 Apache
children of the original root Apache process. All other process identities must
return to baseline. This exception does not permit residual payload processes.
Full configuration/table/source checks pass after each session, and original
factory values restore at the end.

## Harness diagnosis and retained evidence

The first draft records **two examples / one failure** before any payload or
exploit invocation. Readiness succeeds, but a process baseline assigned in one
RSpec example is unavailable in the next example's instance. That is a harness
state-sharing error; no module verdict is assigned. Its frozen inputs, original
exception, native readiness and successful teardown are retained.

The correction stores the baseline, callback route and ready-event location in
the already shared evidence state. The next complete run passes all three
examples. A final replay additionally fingerprints the shell command provider
and Unix escaping implementation. Original failure and successful frames remain
separate. Both use the same payload and success requirements.

The final functional duration is **153.20 seconds**, excluding service startup.

RuboCop reports zero offenses across the three new Ruby files. Module-document
tidy, Compose resolution, opt-in discovery and diff checks pass. The existing
human-written Scenarios section is byte-for-byte unchanged. No full unit suite
is run for this opt-in fixture addition.

## Coverage and cleanup

The latest retained set has **81 cases / 24 profiles**, **31 used/closed OS
sessions**, **270 current declared input fingerprints** and **152 zero resource
event captures**. Historical coverage reaches **325 owners in stated paths,
694 profiles and 4,856 functional cases**. These are covered paths, not a claim
that every behavior of those modules is qualified. The static inventory retains
5,179 source files, 330 registered sources, 42 current reviews, zero stale reviews
and 167 pending exploit candidates with container hints.

The startup inventory finds no running or stopped containers in either local
context, so the requested broader cleanup has no pre-existing containers to
remove. Each test phase removes its own containers immediately afterward. All
**13 new / 544 recorded Docker objects** independently verify absent; both local
contexts finish globally empty, with owned ephemeral networks/volumes absent.
No agent or Docker-backed connector is initialized here.

Only one stack runs at a time. The session phase needs three capped services:
openDCIM at 768 MiB / 0.8 CPU, MariaDB at 384 MiB / 0.4 CPU and reporting
PostgreSQL at 128 MiB / 0.2 CPU. Equal memory/swap limits and PID limits remain
in force. The third service uses the user's explicit allowance for additional
resources and is removed with the phase. Shared instructions continue to require
namespaces, ownership records and cleanup from all agents.

Default fetch sessions, dropper architectures/flavors, HTTP authentication,
other releases and patched behavior remain unqualified. These opt-in tests do
not execute in ordinary unit CI; published-head workflow status is separate.

## Self-review

| Area | Assessment |
| --- | --- |
| Summary | Adds a native-gated Bash session recipe using existing session helpers. |
| What looks good | Real remote use, independent UID/PID/file/reporting evidence, same-selection repeat and complete configuration preservation. |
| Concerns | Default fetch prerequisites are absent; dropper, auth and release variants remain outside this profile. |
| Suggestions | Qualify feasible dropper paths next and continue the full inventory queue. |
