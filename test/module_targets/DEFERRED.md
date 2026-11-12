# Deferred module investigations

These findings do not count as passing functional qualification. The
[campaign](CAMPAIGN.md) and individual verification records retain other
coverage limits and ongoing investigations.

## Ray startup and remaining version coverage

The [Ray job investigation](VERIFICATION-20261111-ray-jobs.md) preserves an
initial native failure before any module call. Ray's dashboard agent reported
five missing-parent observations and exited, triggering Raylet fate-sharing.
The initiating cause is unresolved. Pinned source suggests a psutil creation-time
comparison as one possibility; later stable observations do not establish it.
This is an intermittent native prerequisite failure, not evidence of an owning
module defect. Keep the first failure for future startup diagnosis.

The [CPU profile owner](VERIFICATION-20261111-ray-profiler.md) now passes its
Ray 2.6.3 x64/x86/AArch64 main paths and repeated sessions. Ordinary py-spy
profiling remains permission-denied at default capabilities, while genuine
command substitution and owning sessions still work. A fully working ordinary
profiler privilege variant and additional versions remain separate targets.
The [modern log owner](VERIFICATION-20261111-ray-modern-logs.md) now passes
single-node Ray 2.56.0 path enumeration and exact loot. Its full dashboard's
resource requirements and original native/probe failures are recorded. The
[fixed comparison](VERIFICATION-20261111-ray-fixed-logs.md) now passes seven
owner cases on 2.57.0, with a current eleven-case affected replay and exact
native gRPC/HTTP rejection evidence. Multi-node grouping and smaller-footprint
supported variants remain separate. Job execution on releases beyond 2.6.3 still needs
owning paths. Successful native SDK jobs, source inspection or file-read
confinement do not qualify those remaining module paths or version gates.

## Superset remaining profiles and RCE execution

The [Superset version checkpoint](VERIFICATION-20261111-superset-versions.md)
passes fourteen cases on 2.0.0 and four on 2.0.1 through the shared guarded
selector. Genuine 2.0.1 native escalation and forced gather success exposed
false `Safe` checks in both owners; the corrected version boundary and default
AutoCheck gather now pass. The earlier hostname-reporting loss is repaired,
and explicit JSON signing preserves the legacy String default. Original setup,
assertion and owner failures remain separately sealed.

The manifest explicitly selects the gateway's internal `default` network;
the shared selector and component command use the same verified implementation.
The original two-network refusal remains a harness failure. Other releases,
rotated/custom keys, HTTPS, other database backends, private DNS unavailable to
the operator, and the RCE owner's SQL Lab/permalink/payload/session/cleanup paths
remain unqualified. A successful RCE `check` does not qualify those paths.
The [native RCE preparation](VERIFICATION-20261111-superset-rce-native.md) passes
two genuine SQL/permalink/deserialization and cleanup cycles. The
[owner investigation](VERIFICATION-20261111-superset-rce-owner.md) confirms and
repairs original permalink byte corruption. Its owning shell was used and
closed; the earlier owning Meterpreter shutdown retains CLOSE_WAIT sockets.
One created permalink row remains, blocking the strict state guard and later
cases. The intended residual-artifact contract needs investigation. Draft SQL
expectations were corrected from actual normalized service/login rows, with
status/attempt timestamps and repeat behavior still unqualified. The profile
is excluded from passing totals; its five failures are not five owner defects.


## MinIO remaining coverage and retained failures

The [MinIO checkpoint](VERIFICATION-20261111-minio.md) passes the final six/three
examples, fourteen client states and 22 post calls. The original invalid JSON
loot is a verified owner defect, repaired by full-document serialization.
The 632-entry original failure and 811-entry timeout remain historical evidence.
The timeout's incomplete Meterpreter fixture restoration and unreached states
are not retroactively qualified by its successful native or physical cleanup.
Final 841/439-entry cohorts supply the actual passing evidence.

Windows shell, Windows Meterpreter, Windows PowerShell, macOS, other Unix,
other architectures/delivery modes and additional releases remain individually
pending. The Linux shell default path uses an explicit real HOME export;
unconfigured HOME is not qualified. Source compilation and multi-node storage
controls are prerequisites, not module success by themselves.

## PHP 5.3/macOS UDP channel CI investigation

Head `69f779414da` finishes with 62 successful checks, one skip and one failing
[PHP 5.3/macOS Intel job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42937416882/job/130250815806).
Its 91-example suite has one failing stageless TCP session/socket-channel case.
`[UDP] Has the correct peer information` raises `IO::EAGAINWaitReadable` during
receive, before peer-field comparisons. Subsequent distinct UDP channels receive
and send data successfully. This does not establish incorrect peer metadata.

Source investigation independently reproduces a payload/address framing race:
the local channel writes two datagrams, and an intervening read consumes payload
before the address is available. Forced schedules also reproduce mispairing and
incorrect peek behavior. Critical source matches cached upstream merge-base
`7673832c30657be675656b53ece208759314bed7`; exact CI-event attribution remains
unproven without local frame timing/backtrace or a matching runtime reproduction.

A complete-record queue proposal remains deferred because native inherited IO
methods could expose a private notification or require broader buffering/API
work. Removing public IO capabilities is not accepted as a workaround.
Production channel code is unchanged. A test-only uncommitted draft hit a
load error before executing examples; that is not evidence of a fixed defect.
The nine-file investigation export is retained at
`/Users/dwelch/.codex/reports/meterpreter-udp-framing-deferred-20261111-69f779414da/`,
manifest `59d98fd3451af8327c8c878a3992f80036df285a4d79383e60b5376b6d8e7d35`.
The official job log is separately retained with SHA256
`56a00132258acbb8d8f51c90e4f887225a9e3497605e0db3e294789ed5337a59`.
No CI retry, matched base/head runtime or compatible production fix is claimed.

## Gogs remaining platform and repeatability coverage

The [repository checkpoint](VERIFICATION-20261110-gogs-repositories.md) passes
all 25 cases after correcting the two capture-backed observer mismatches.
Existing-repository canonical refs, seed parent, feature content and no-extra-ref
gates now execute successfully. Fixed missing-path proof retains the raw native
branded404 body/hash and exact reason-bearing Safe/service state. The earlier
five/three and five/one failures remain preserved by the
[partial checkpoint](VERIFICATION-20261110-gogs-rebase.md).

Windows, other architectures and same-instance state reset remain pending.
Existing-repository repetitions use fresh owned seeds; repeated exploitation of
an unchanged repository is not qualified. Closed PR history, objects and merge
caches remain observed state until explicit operator seed removal. Native token
revocation remains distinct from automatic module cleanup.

## Flowise remaining coverage and historical fixture failures

The [current checkpoint](VERIFICATION-20261111-flowise-recovery-sessions.md)
passes all six selected profiles 12/0 after fixture corrections. Exact 3.0.1,
Windows, application HTTPS, other roles/branches/payloads and the CSV-agent owner
with real model inference remain individually pending. Trusted SMTP certificates
are not qualified; the lab explicitly uses unverified local SMTP TLS.

The historical 483- and 557-entry exports preserve the original replay-status,
mail-argument, package-export and host session/readiness failures. The current
599-entry export retains the genuine passing rerun. Strong account-row and
distinct-password replay proof, complete mailbox prefixes, publisher hashes,
bootstrap readiness, remote PID absence and supported host closure remain
required. Earlier partial iterations and failed families are not retroactive
passing coverage; no production owner/core repair is claimed.

## Mettle CI cancellation at `89b7bca8f36`

The previous public head has 62 successful checks, one skipped check and a
cancelled [Mettle Ubuntu job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42925707613/job/130211519024).
Its retained log contains successful binary-data output followed by nine repeated
send-timeout reports in filesystem/process tests, then cancellation after about
60 minutes. The suite does not complete. Source and cancellation causes remain
unclassified; trigger metadata does not identify a cancellation actor, and
missing replies do not establish wire silence. No matched base/head runtime,
production repair or retry is established.

The eight-entry official-log/API/workflow assessment verifies at
`/Users/dwelch/.codex/reports/mettle-ci-cancellation-20261111-89b7bca8f36/`,
manifest `39fc9641ce9e48ec2377fcab7abea07b438971f7e009f3de28e51b4185d4210a`.
The earlier search-setup stall and macOS bootstrap failure below remain separate.

## macOS Python CI console bootstrap

Head `5a5c080eef6` has a failing
[Python3.11/macOS job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42918858994/job/130188249730).
All 91 examples inherit a shared first-prompt timeout before any Python payload,
session or owning module runs. The child remains alive with only the existing
OpenSSL configuration notice; the startup phase and cause are unknown. No
matched base/head runtime or repair is established. A bounded cold-startup
diagnostic must preserve phase/load progress and child CPU/RSS/thread evidence.
The verified 13-entry assessment is retained at
`/Users/dwelch/.codex/reports/python311-macos-ci-assessment-20261110-5a5c080eef6/`,
manifest `183e483e7ab773f5571ab6042495bd70e036dce95fe5017458eed06729392aae`.

## Mettle HTTPS acceptance setup stall

Fork head `6ab53da687b` finishes CI with 62 passing checks, one skipped check and
one failing [Mettle job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42901683015/job/130128980930).
Its Linux x64 stageless HTTPS/base64 `post/test/search` example stalls during
setup's initial file deletion, before any search assertion. The matching
`stdapi_fs_delete_file` request appears in Framework TLV and payload debug
captures without a recorded reply; later heartbeat/allocation records do not
prove successful network exchange. Cleanup also stalls.

The cause remains unclassified. Prior similar CI stalls were not reproduced by
the earlier local two-case pass, and no matched campaign-base/head runtime
comparison or production repair is established. A bounded Ubuntu reproduction
needs labeled handler/worker and HTTP queue evidence at the first unanswered
request. Raising timeouts or retrying alone would not establish a repair.
The independently verified 17-entry assessment is retained at
`/Users/dwelch/.codex/reports/mettle-search-ci-assessment-20261110-6ab53da687b/`,
manifest SHA256
`75fa3de7eb087c5e7955ebd79fd0d804bbc57682ef52ddf9d961c668fdd5cdc1`.

## WordPress administrator upload sessions

`exploit/unix/webapp/wp_admin_shell_upload` remains unqualified. Its retained
[25-case reproducer](wordpress_admin/README.md) documents the cold-state seed
7721 and genuine WordPress/PHP native controls. Repeated staged PHP Meterpreter
execution can enter an invalid-session reconnect burst during bootstrap.
Interrupted full-profile attempts retain null counts; a bounded observer case
finishes with one failure and successful teardown. Neither is passing coverage.

Independent role/authentication, actual proof-plugin upload/execution/removal and
native PHP callback controls pass. Explicit remote exit and prior-handler
shutdown do not resolve the staged-session failure. Saved TLV observations narrow
the investigation to bootstrap/`core_loadlib` and packet transport, but lack
session/socket labels; a missing decoded reply does not establish wire silence.
The upload module has not been established as the cause, and no production
session repair is claimed.

The separately integrated upload-permission check repair passes matched ordered
20/5 to 20/0 and focused 21/9 to 21/0 comparisons. It does not qualify session
execution. Current module source SHA-256 is
`d1e640a23c27d6c2b983380b44bc4c8c493a003fefe35573994c9dad43474924`.
The [retained verification record](VERIFICATION-20261109-proxy-history.md#retained-investigation-and-remaining-work)
records independent verification of all 338 session-export and 95
permission-export checksums. Keep those failures separate from the verified
permission repair. Further work needs labeled session/socket transport evidence
through the second staged bootstrap before selecting a module or session fix.

## Ansible node deployment

`exploit/linux/local/ansible_node_deployer` remains unqualified. The native-passing
original baseline completes eight cases with six failures. Independent controls
confirm foreground node payloads blocking playbook completion, controller files
being cleaned through a node session, and selected-host calculation failures.

An isolated experimental repair improves focused tests to 23/0 and addresses
those paths. Its split functional profiles have raw 4/0 plus 4/0 counters, but
an independent audit finds a positive operator abort despite a full play recap,
actual node proof and restored files. Those counters are explicitly rejected.

A direct diagnostic returns a full recap without the success marker after
37.0165 seconds despite a sixty-second collection setting. Its independent
native exit record is absent, so its actual exit remains unknown. A final
bounded comparison obtains genuine native exit zero, node command/identity
proof and payload removal in both asynchronous and foreground modes, but both
redirect stdout. That changed collection condition does not explain the
original direct-call failure. No shared-helper repair is established.

The retained worker is
`/Users/dwelch/.codex/worktrees/ansible-deployer-validation/metasploit-framework`.
Its experimental source SHA-256 is
`1ae6f11c7e1da0c186f830cf2ca680d830679b31883b106d6531712e905872ea`;
that source is not integrated or published by this checkpoint. The durable
`ansible-deployer-diagnostic-checkpoint-20261109T221656` export retains every
baseline/diagnostic, exact source/input snapshots, native controls, proposed
patch and explicit `UNQUALIFIED.json`. The parent independently verifies all
939 checksum entries; the manifest SHA-256 is
`47f53c3e4c5a7f6d389b0f96b331c9c888fff31c3bcb04a8249c379bc7c745fc`.
The worker's final audit records all fourteen owned projects and fourteen
recorded volumes absent. No experimental source commit or PR is claimed.

Further investigation should independently capture native process completion
and exact returned bytes on an ordinary direct call before selecting a
transport or module workaround. Passing redirected commands, session counts,
recaps and focused examples alone do not qualify this deployer.

## Grafana SQL expression command delivery

`exploit/multi/http/grafana_sql_expressions_rce_cve_2024_9264` remains unqualified
outside its selected 11.0.0 Linux command/Bash coverage. The
[qualified corpus](VERIFICATION-20261110-grafana-expression.md) now passes 14/0,
including four owning sessions and two separate real Bash calibrations.
Genuine Grafana 11.0.5 SQL scalar/file controls pass with
both authenticated Viewer and anonymous policies. The corrected original-module
baseline `20261110T154643-3d7cd7` finishes 14 examples/four failures: quoted
Generic and reverse Bash delivery fail under both policies; fixed and
missing-binary profiles each pass their two cases. No owning session is proved.

The Unicode request advertises 4,566 bytes while sending 4,567, and the server
reports `unexpected EOF`. The integrated byte-string encoding repair preserves
the JSON and command bytes and passes matched 2/1 to 2/0 request-emission tests.
Shared Rex code is unchanged. This fixes the request-length defect, but does
not establish command execution. The ASCII Bash request reaches a separate
vendor error: `Only SELECT statements can be serialized to json!`.

The earlier 14/11 result is retained separately: Generic calls stopped at
FileDropper's required `AllowNoCleanup` option, and anonymous cases inherited an
incorrect authentication-policy assertion. Those failures are not eleven module
defects. Corrected fixtures retain strict command/session/cleanup assertions,
record output paths even when a helper raises, and distinguish anonymous Viewer
access from successful authentication of supplied incorrect Basic credentials.

A separate official 11.0.0 native comparison passes ordinary API controls but
both original and tab-variant command probes stop at an unwritable service cache
path, `/usr/share/grafana/.duckdb`. Both markers are absent. CLI/build HOME was
`/var/lib/grafana`; the vendor entrypoint exports HOME from `GF_PATHS_HOME`.
Actual service PID environment/cwd and API engine/home observations were not
captured, so CLI extension success does not prove the service prerequisite.
Neither algorithm is classified from this cache failure. A subsequent isolated
service-cache comparison passes with the unchanged vendor startup and security
policy. Actual PID1 and CLI HOME/cwd are `/usr/share/grafana`; the API identifies
DuckDB 1.1.2, signed-extension enforcement and the installed, initially unloaded
shellfs cache. Both original and tab-variant API batches produce exact separate
UID472 markers and restore state. This is native observation independent of
Framework execution; the original algorithm was copied for diagnosis.

The subsequent Framework invocation `20261110T171141-3be751` finishes 14 examples
with four fixture/cascade failures: affected 11.0.0 is 7/1, independent fixed
11.0.5+security-01 is 2/0, missing-binary 11.0.5 is 2/0, and anonymous-prefix
11.0.0 is 3/3. Generic command proofs pass before foreground shell entry.
Plain `run` then enters the actual CommandShell dispatcher, so later `sessions
-K` and `back` reach that dispatcher or remote shell instead of msfconsole.
Subsequent calls without an owning request cannot establish module delivery.
The subsequent 82-input calibration run stops before positive owning calls on
a file-transfer permission error (14/10 inherited setup failures). The copied
file's owner/mode were not captured. The final helper creates exact stdin bytes
as UID472 and verifies native owner/mode/hash, then independently calibrates
real CommandShell use/exit/PID/host-close before the successful 14/0 run.
The original 72 inputs and failures remain preserved; no algorithm change is
justified by these console failures. All four profiles pass owned teardown;
the parent repeats 16 exact-object absence checks, 12 project-label queries and
an empty global container inventory after removing unrelated tool containers.

All completed profiles retain passing owned teardown. The corrected baseline
export is `/Users/dwelch/.codex/reports/grafana-expression-corrected-original14-20261110-3d7cd7/`
(282 entries, manifest `a561b65ae24c02037726a128f9dd45ecca6943d9125b87e33862d1301212eaa4`).
The legacy native/encoding export is
`/Users/dwelch/.codex/reports/grafana-expression-legacy1100-native-20261110-e2d165/`
(209 entries, manifest `f767aa338667b88866bc80beb1609f71e25338726bebbb1b663e5d7e90e2935a`).
These retained failures add no passing module or functional case to the checkpoint.

## Salt deployer Python HTTPS master termination

The native Linux Meterpreter/Unix shell matrix is qualified separately. A real
Python HTTPS master session successfully ran the owner and all three hosts had
no remaining module files, but its exact remote PID/birth identity remained
alive after public shutdown. Cause is unverified; the latest fresh-RPC/dependent
shutdown sequence has not been qualified for that transport. Preserve this as a
transport/lifecycle investigation rather than assuming another owner defect.
See [the verification report](VERIFICATION-20261112-saltstack-deployer.md) for
sealed runs, resource-invalidated results and scope. Other Salt versions,
non-root masters and exceptional paths remain untested.
