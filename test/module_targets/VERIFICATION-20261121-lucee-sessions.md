# Lucee default Bash sessions and automatic cleanup

The new [Bash session profile](lucee_bash/README.md) qualifies **2/0/0** with
**three real sessions used and closed**: one stock independent handler session
and two actual module sessions. The actual console defaults select Unix target
0 and `cmd/unix/reverse_bash`. Both owner executions leave `AllowNoCleanup` at
its normal **false** value and prove automatic FileDropper removal of their
CFML source and temporary directory before fixture cleanup.

Eleven previous profiles retain 42 cases and thirteen used/closed sessions with
unchanged declared inputs and retained raw proofs. The latest twelve-profile
set therefore has **44 qualified cases and sixteen used/closed sessions**.
One new profile and two cases bring the campaign to **321 runtime owners, 682
qualified profiles and 4,819 historical functional cases**. Replays do not
inflate these totals. The broader inventory remains incomplete; no PR is created.

## Genuine target and independent readiness

The target retains the official Linux amd64 **Lucee 5.3.7.43** image at digest
`sha256:2c4c766b5382e3969bc603803629ad28f5c6c26efc93e59b0be514b3c4aa498c`.
Native probes establish Java **11.0.8**, UID **0**, the real context/webroot
paths and no scheduled jobs. The genuine JAR fingerprint matches before and
after the accepted run:
`0a17b6c6c647959eabcb96245b4fb6ab3d5dc0a86462b55d83510f0f18aa7932`.
Vendor code, production modules and libraries are unchanged.

The existing image has Perl **v5.28.1** and JSON::PP **2.97001**. The profile
reuses the existing Perl `/proc` observer and public session/reporting controls;
it does not install an interpreter into the target. The observer records PID,
parent, birth time, UID, executable, command line, TCP state and socket inodes.
It excludes itself, the exact health probe and transient `runc init`; released
TIME_WAIT entries are separated from active connections.

Independent Bash and genuine CFML first produce the same physical readiness
bytes. A native request to the real image-write route proves physical CFML
source, its trailing LF, interpretation through `/lucee/`, and removal. A native
Perl callback then proves the Docker-host route, acknowledgment and exact
socket-inode ownership by an independently observed live PID.

The first test uses the real multi/handler and its generated stock
`cmd/unix/reverse_bash` bytes. A separately installed script launches the payload
directly, bypassing the module and CFML delivery. The session must execute the
proof command, produce exact UID-0 file bytes, have the correct original
reporting row, and close through public APIs. It returns to the original process
set with no active callback connection. Owner execution is withheld if this
independent payload/handler gate fails.

## Actual default owner, repeat and FileDropper

The first actual module attempt omits both TARGET and PAYLOAD from run options.
The raw TARGET datastore entry is `nil`; the public `target_index` accessor
resolves the effective default to **0**. The observed payload is
`cmd/unix/reverse_bash`, and `AllowNoCleanup` is false. The repeat explicitly
uses the same target and payload on the same selected console object, with
AutoCheck disabled. The first attempt runs the actual reason-bearing Appears
check. Both actual exploit bodies and encoded Bash commands are observed.

Read-only method events capture the physical CFML file immediately after the
real `write_cfml_stub` returns, before command execution. Native reads verify
UID 0 and exact bytes matching the actual module-generated source plus the
vendor writer's LF. The temporary `__` directory exists at that boundary.
No source producer, HTTP response or cleanup implementation is replaced.

The normal FileDropper `on_new_session` path then receives the real session.
Its original registry contains the uploaded file and `__` directory. Events
record the actual file and directory deletion helpers from the unchanged
FileDropper library. At return, both registries are empty; independent native
reads establish file and directory absence. The fixture never manually deletes
either owner stub. Both iterations prove this boundary before session proof
file cleanup occurs.

Each session is the only active Framework session and has exactly one open
reporting row. A public shell command writes the exact proof marker, reports
its PID and returns UID 0. The native observer binds that PID and birth identity
to the sole established callback socket by inode. The SQL row's original ID,
owner and payload match session metadata. A fresh shell response precedes public
remote exit; normal Framework session/job cleanup follows. The original SQL row
gets a nonempty `closed_at`, every new payload/launcher process disappears, and
the complete observed process set returns to baseline between attempts.

| Current accepted session | Delivery | Verified outcome |
| --- | --- | --- |
| Independent stock handler | Direct native script | Physical proof, PID/socket ownership, original row closed |
| Owner, iteration 0 | Observed console defaults, AutoCheck on | Same session proofs and automatic source/directory deletion |
| Owner, iteration 1 | Same selected module, AutoCheck off | Same proofs, cleanup and complete return to baseline |

The final functional suite takes **111.28 seconds**, excluding target startup.
An initial passing frame also used/closed three sessions; it is retained as
historical evidence. Only the final frame supplies the current-input session
qualification and the new profile's two-case addition.

## Retained harness observations

An early tool inventory lists the actual installed executables, but its JSON
formatter rejects Perl's blessed version object. The maintained probe explicitly
serializes the version as a string and records the real runtime above. This is
an inventory collector issue, without module execution.

The first maintained frame fails **2/2** in before-all setup because the harness
expects raw TARGET to contain 0. It actually contains `nil`, while Framework's
unchanged `target_index` implements the normal default fallback. Independent
CFML, physical image-write and callback controls have already passed, but neither
the stock session test nor the owner runs. The original frame remains failed,
with session/owner verdicts withheld. The assertion now uses the public effective
target accessor rather than assigning TARGET or changing selection behavior.

The corrected frame passes **2/0**. Its real captures establish single-socket
ownership and one open reporting row per session. Those observations become
explicit maintained assertions, and the final normal-launcher replay passes
**2/0/0**. No production repair is justified by these results.

## Inputs, checks and resource cleanup

All **141 current declared inputs** reconcile. The fresh profile has eight zero
memory/PID event captures; the retained profiles add 56, giving **64 qualified
zero captures**. Retained cases/sessions are current-input historical proofs,
not new runs in this tranche.

At most **two capped containers** run together: Lucee at 1 CPU, 768 MiB
memory/equal swap and 128 PIDs, plus disposable PostgreSQL at 0.2 CPU, 128 MiB
memory/equal swap and 64 PIDs. Published ports are loopback-only. All phases use
the task namespace and shared heavy-work lock. No agent or tool helper starts.

The tool inspection and all three functional frames are removed immediately.
Their **seven containers and three ephemeral networks** are independently absent.
Rechecking the prior 405 objects establishes **415 absent recorded objects**.
Both Docker contexts show **zero containers, including stopped containers**;
no owned ephemeral network or volume remains.

Four new Ruby files pass RuboCop. The changed module document passes tidy with
no messages. Its original **8,277-byte Scenarios tail** is unchanged, with SHA256
`203b92b8ee6f7d6104aaa5e2d40c7c48ebc92eb009a2992ae0bd9d4b7cc72bcb`.
Automated observations do not supply human Scenarios.

## Evidence and remaining scope

Immutable capsules under `/Users/dwelch/.codex/reports/` retain frozen inputs,
raw native/console output, real method events, physical sources, process/socket
snapshots, reporting rows, audits and exact cleanup identities. Publication
separately binds final documentation and committed blobs.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `lucee-session-unset-default-target-20261121T061533` | 95 | `c5f3eef66aed81dfa517451dc7bcaf122db0e65cb85052cbb2f63cfffb58ed37` |
| `lucee-default-bash-initial-pass-20261121T061818` | 84 | `69b6dd6f8c79584eb939b1499cb5ba43d117775c956ed6c918e126e5a93fd779` |
| `lucee-default-bash-maintained-20261121T062140` | 237 | `b7d1ea07c56e3783738c084afff22e3f09f9d00c56f62cddae4401f0c80e069c` |

Linux dropper targets and architectures, the authenticated scheduled owner's
sessions, non-root deployments, Windows, IPv6 and other releases remain
unqualified. Existing Calibre, PHP Meterpreter, Ignition log-state and Laravel
duplicate-callback investigations remain open. Genuine fixed-release command
withholding remains covered by the [previous report](VERIFICATION-20261121-lucee-fixed.md).

## Self-review

**Summary:** The default Unix session path and real automatic FileDropper cleanup
gain short native-gated coverage, including a same-selection repeat.

**What looks good:** Independent stock readiness, exact physical source/proof
bytes, original reporting IDs, PID birth/socket ownership and full process-set
restoration distinguish real success from a session counter or cleanup message.

**Concerns:** The listed delivery/platform variants and full inventory remain
incomplete. The failed setup frame is retained with no module verdict.

**Suggestions:** Cover the Linux dropper family and scheduled Unix sessions next,
then continue valuable uncovered owners with independently verified prerequisites.
