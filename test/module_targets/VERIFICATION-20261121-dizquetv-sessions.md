# dizqueTV Bash sessions and live state recovery

The [Bash-session profile](dizquetv_sessions/README.md) passes **four examples /
zero failures / zero pending**. It uses and closes four real shells: stock CLI
and independent API controls, then two original owning sessions. Full settings
recover while shells remain live. No production module source changes or PRs
are needed. The full module-inventory goal remains active.

## Native prerequisites and delivery

The profile extends the unchanged, pinned publisher **1.5.3** image qualified in
the [command report](VERIFICATION-20261121-dizquetv.md). The real API reports
embedded Node **v12.16.2** and FFmpeg **4.3.5**, and the application binary retains
its pinned fingerprint. No standalone Node, Python, PHP, curl or wget is present.
Native observations use stock Perl core plus host Python's standard libraries;
no target package is installed and no application method is replaced.

The original command controls prove CLI/API command output, UID-0 file bytes and
complete state recovery before session testing. A token/acknowledgment callback
then proves the actual container-to-host route, UID, PID/start time and socket
inode. The first stock Bash payload runs through the existing real handler and
an independently hashed native script. Its shell executes a command and writes
exact proof bytes, then exits gracefully. Script, output and proof absence verify.

A second stock handler command goes through the actual public ffmpeg-settings
and version APIs. The independent version request remains pending while the
foreground shell is live. A separate API connection restores the original
settings before proof and shutdown; the pending request completes normally with
HTTP 200 after shell exit. This qualifies the real primitive and live restoration
before the module is attempted.

## Actual owner and cleanup

Both original module executions use explicit `cmd/unix/reverse_bash` and empty
COMMAND. The first leaves TARGET unset and observes default Linux target 0 with
AutoCheck enabled; the repeat explicitly selects target 0, disables AutoCheck
and retains the same selected console module. Actual check events match Appears
only on the first attempt. The exploit bodies remain at their real source paths.

The original five-second version-request timeout runs unchanged. Both original
PUT requests are captured: the exact encoded payload in ffmpegPath, then complete
original settings. The instance's saved settings clear. The module returns
without requiring shell exit; all nine root JSON stores and the API state already
match the non-default baseline while the shell is still usable. No Windows upload
method is called. Static-page health continues to answer.

Public shell APIs create exact `dizquetv-session` proof bytes owned by UID 0.
Independent procfs observations match the shell PID/start time and its established
callback socket inode. A fresh command response precedes graceful remote exit.
The original reporting session row must change from open to closed with the same
ID and owner/payload metadata. Framework jobs and sessions empty; the complete
process identity set and callback sockets return to baseline. All four proof
files are deliberately removed and absence checked. Native script/output files
are also removed and their absence checked. These are fixture artifacts, not
claims about automatic module file cleanup.

The vulnerable fixture's thread count stays at the seeded value 2 throughout.
The full nine-store baseline preserves after every operation, and factory value
4 restores at the end with the binary fingerprint unchanged.

## Retained first failure

The first frame has **four examples / one failure / one pending**. Its stock CLI
session succeeds and closes, but the new API-control helper reads `job.ctx.last`
as the payload. The actual driver context holds exploit, payload, run UUID and
job listener, so `.last` is `Msf::Simple::NoopJobListener` and has no `refname`.
The existing Laravel helper correctly reads the second element.

The corrected helper uses index 1. The first frame, frozen inputs, exact console
error, native session proof, settings recovery and successful exact teardown are
retained separately. Neither the native API nor the owning module is invoked in
that failed frame. This is a harness fault, not evidence of a module defect. The
corrected complete profile passes on its first replay.

## Results, resources and scope

The four examples take **156.86 seconds**, excluding startup. The latest retained
set reaches **107 cases / 31 profiles**, **47 used/closed OS sessions**, **317
current declared input fingerprints** and **216 zero cgroup-event captures**.
The 103 earlier cases retain matching inputs. Historical coverage reaches
**326 owners in stated paths, 701 profiles and 4,882 cases**; those counts do not
prove complete module coverage.

Only two capped containers run: application **384 MiB / 0.7 CPU / 96 PIDs** and
reporting PostgreSQL **128 MiB / 0.2 CPU / 64 PIDs**, with equal memory/swap caps.
The reporting database uses temporary memory-backed storage. All **six new /
582 recorded Docker objects** independently verify absent, including the failed
frame. Both local Docker contexts finish globally empty, and owned ephemeral
networks and volumes are absent. No agent or Docker-backed connector starts here.

Three new Ruby files pass RuboCop with zero offenses. Python/Perl syntax, Compose
caps/configuration, module-document tidy and default RSpec discovery pass; the
new Docker profile is excluded from ordinary unit CI. Existing human-written
Scenarios output is unchanged. No full unit suite is run. Exact published-head
CI is observed separately; Docker functional results come from the local profile.

Default fetch delivery, Windows, other payload families and other releases remain
unqualified. The stock missing curl/wget prerequisite is retained; no replacement
fetch executable is installed to manufacture a default-path pass.

## Self-review

| Area | Assessment |
| --- | --- |
| Summary | Adds the real Bash-session path to the already qualified Linux command owner. |
| What looks good | Native CLI/API gates, live full-state recovery, exact proof and process/socket/reporting closure; failed harness frame is retained. |
| Concerns | Default fetch, Windows and other delivery/release paths remain unqualified. No production module fault was reproduced. |
| Suggestions | Continue the full valuable/container-feasible inventory and retain native prerequisite gaps rather than treating them as exclusions. |
