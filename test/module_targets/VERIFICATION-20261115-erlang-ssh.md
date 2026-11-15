# Erlang OTP SSH execution validation, 2026-11-15

Four genuine Erlang SSH profiles pass **36 functional cases and 64 public
owning-module calls**. This adds one runtime owner and four profiles, advancing
recorded campaign coverage to **256 owners, 379 profiles and 3,291 functional
cases**. Earlier modules retain their recorded paths and inputs; this is not a
whole-campaign replay.

| Profile | Actual OTP / SSH | Target identity | Cases | Owner calls | Fixture revision |
| --- | --- | --- | --- | --- | --- |
| `erlang_ssh` | 27.3.2 / 5.2.9 | Root, UID 0 | 9 / 0 failures | 16 | `919ba0fa8ae` |
| `erlang_ssh_nonroot` | 27.3.2 / 5.2.9 | Named `module_target`, UID/GID 1000 | 9 / 0 failures | 16 | `919ba0fa8ae` |
| `erlang_ssh_fixed` | 27.3.3 / 5.2.10 | Root, UID 0 | 9 / 0 failures | 16 | `919ba0fa8ae` |
| `erlang_ssh_versionless` | 27.3.2 / 5.2.9 | Root, genuine vendor `id_string = Erlang` | 9 / 0 failures | 16 | `2fd47f3a6ed` |

All four use identical repaired production source, SHA256
`c8ae9f5d067c1e0e74f25c2f778be2be3d3fc7addc6791ef214889a010c953eb`.
The last fixture revision changes only process-ancestry observation, as detailed
below. The earlier three profiles retain their exact frozen passing inputs;
they were not replayed with that final observer. The final versionless profile
uses the corrected observer. This is qualification of these recorded profile
paths, not a claim that every profile ran the current harness revision.

## Genuine target and prerequisites

The fixture uses digest-pinned official OTP 27.3.2 / SSH 5.2.9 and OTP 27.3.3 /
SSH 5.2.10 images on linux/amd64. The vendor `ssh:daemon` implementation is
unchanged. Exact installed versions and `ssh_connection.beam` hashes are
independently checked. A real password account accepts its correct password,
rejects a wrong password, and executes an ordinary authenticated command before
and after preauthentication requests. Affected requests must create exact nonce
files; the patched daemon must refuse the same requests and remain usable.

The vendor identifies separate maintained-branch fixes in
[GHSA-37cp-fgq5-7wc2](https://github.com/erlang/otp/security/advisories/GHSA-37cp-fgq5-7wc2).
The fixture's actual SSH application versions straddle the 5.2.10 fix. Focused
units also exercise 4.15.3.12 and 5.1.4.8 boundaries from vendor tag sources;
those older branches are not runtime-qualified here.

Native payload calibration uses the real multi/handler and its already-generated
command bytes. Both module-default delivery families must open real sessions:
`cmd/linux/https/x64/meterpreter/reverse_tcp` and `cmd/unix/reverse_bash`.
Their real session APIs write exact nonce files. Independent target inspection
verifies PID/UID and process ancestry. Remote shutdown must precede local shell
closure; SQL must record closed sessions. These native calls add no owning-module
qualification or functional case counts.

## Original behavior and source repair

The original affected daemon accepts both independent simple and quoted native
requests. Original Framework simple and AutoCheck-disabled simple commands
create the expected files, but a double-quoted command does not. The original
console's actual CMD value is verified, excluding quoting loss in that capture's
resource-file setup.

The original stock-patched check returns Safe and saves no vulnerability. Forced
execution prints `Payload executed successfully` without creating any file.
The captured replies are SSH_MSG_KEXINIT (message 20), including replies to
failed quoted requests. The original `000003` test examines packet-length bytes
and provides no execution proof.

The scoped repair escapes quotes/backslashes in the Erlang expression, frames
SSH string/packet lengths in bytes, uses configured SSH_IDENT, reads one bounded
plaintext KEXINIT and always disconnects. Dispatch prints an unconfirmed status.
Check uses precise passive Erlang SSH versions with reason-bearing Appears,
Safe, Detected or Unknown results; it sends no execution request. The confidence
change follows the absence of direct execution proof in check. Targets and
their default payload metadata are unchanged.

The same final 46-case focused suite, seed 7721, produces original **37 failures**
and repaired **0 failures**, with no pending or outside errors. The patched
original Safe example passes. Hrr encoders and Rex versions are real; network,
UI, reporting and generated payload boundaries are explicit doubles. The primary
worktree independently repeats **46 examples / 0 failures**. This unit result
does not establish genuine Erlang Unicode parsing or successful payload sessions.

The separate worker seal contains 222 independently rehashed entries; manifest
SHA256 `936b68b51c7fcbe01f05b1e037af601ff776317b5b18a3272fe7582ff174b9c8`.
Strict original/repaired lint has the same three baseline offenses:
ModuleDefaultPayload twice and ModuleDuplicateOption. Module tidy exits 2 solely
from those baseline checks. No new module/spec offenses are introduced.

## Preserved harness corrections

The first raw native probe waited for channel confirmation before sending exec;
this prevented the vulnerable sequence from being exercised. A later fixed
probe incorrectly required an explicit disconnect packet when the genuine
patched server closed TCP. Both attempts are retained separately from corrected
native controls. Initial ARM64 emulation was replaced with native amd64 after
verifying the host/daemon architecture; it adds no owner qualification.

The first container-session calibration failed before any owning call because
Docker's target `/tmp` tmpfs was mounted noexec. The exact native launch log
shows Permission denied and `/proc/mounts` independently confirms noexec. The
corrected fixture permits execution for the native fetch family. Python imports
also generated bytecode inside the fingerprinted fixture directory; `python3 -B`
prevents that mutation. The 118-entry failed-attempt seal has manifest SHA256
`35f1e73ebebdd851caf6407f65e124624bb407b16a51430346e1a79542fd62da`.

After those corrections, both native payload/session calibrations pass. The
unchanged owner's first confidence assertion then fails as expected: it returns
Vulnerable without hard execution proof. Only one functional case is reached;
the remaining cases are unrun. This 119-entry seal has manifest SHA256
`1d2f46efd50294b4fd2eff1dcf1fc6423cef7feacb1d4258ea20858c01c6dd6b`.

The first repaired replay passes both passive checks, then exposes a fixture
observation error: inline run options live on the executing instance, while the
console selection's CMD is nil. The fixture now records effective options
through Framework's passive on_module_run event. No owner method or result is
replaced. Its 122-entry seal has manifest SHA256
`ed164105c5e8b9b669f19a4803d3d2ac3ae525d2fac374df4d52bdfeab5c40af`.
The monitor also encountered a container vanishing between inventory and inspect
during genuine teardown; exact final cleanup queries still pass. The corrected
monitor records such disappearance races separately from resource violations.

Each completed attempt verifies six independent cleanup queries and a released
global pipeline lock. The whole existing human module guide, including Scenarios,
is byte-for-byte preserved.

## Unicode interpreter finding

A genuine repaired-owner replay reaches four cases: passive checks, quoted
commands and literal backslashes pass; Unicode fails. A passive execution event
records the exact intended UTF-8 CMD, while an independent native file read gets
`cafÃ©` and the double-encoded snowman bytes. This is interpreter behavior beyond
correct SSH string lengths. The complete 128-entry attempt is sealed with
manifest SHA256 `b828f26deebd97bb927144e6cd67741315f64662acc1e40811c053215a36e880`.

Two independent native requests on the same OTP 27.3.2 / SSH 5.2.9 release use
ASCII Erlang codepoint escapes and create the exact intended café/snowman UTF-8
files. Correct/wrong-password and subsequent authenticated execution remain
healthy; all six cleanup queries pass. There are no Framework owner calls in
that control. Its 75-entry seal has manifest SHA256
`4c4b373fc2ea7fd2429767b2603ad0f15ddc0c871a19f3fda73450a38b3274d4`.
The follow-up validates a local UTF-8 duplicate and emits non-ASCII codepoints
as ASCII Erlang escapes. Invalid byte sequences fail BadConfig without mutating
the command. The same final 52-case suite, seed 7721, gives the first repair
**8 failures** and this follow-up **0 failures**; neither has outside errors.
The primary worktree independently passes **52 / 0** after reducing capture
metadata to a portable archive identifier and adding vendor source links. The
module source itself matches the sealed follow-up exactly.

The follow-up worker seal contains 91 independently rehashed entries, manifest
SHA256 `348f81d6af46663c187f55653d33852c91a5e05a25e921a436ff635a37c9097e`.
The primary worktree's strict six-file lint finds only the same three baseline
module offenses; the focused spec and four fixture/spec Ruby sources introduce
none. Native controls now include the broader Unicode marker before and after
each profile and shorten reply-free positive reads while retaining bounded,
independent target-file proof. The final recorded results appear below.

## First complete serial-profile attempt

The frozen four-profile attempt ends with 24 reported cases / 12 failures, with
no outside errors. Those counts include nine inherited before-all failures in
the non-root profile, not nine module defects. Root, fixed and versionless
profiles each reach five cases and stop on an unregistered fixture option:
ExitOnSession belongs to multi/handler, while the fixture also passed it to the
owning exploit. The real affected root/versionless Linux payload opens a
Meterpreter session before the assertion stops proof. Exact Unicode command
bytes pass in both affected banner modes. No profile is qualified by this run.

The non-root native Meterpreter calibration fails in getuid before any owner
call. Independent capped, read-only probes against its exact old image verify
that UID 1000 has no passwd entry while root does. The corrected image creates
a real named UID/GID 1000 account, which native preflight now checks explicitly.
Unmapped numeric UID behavior remains a separate session-API limitation. Failed
calibration cleanup also preserves the original exception instead of masking it
with a leftover-session assertion.

All four stacks are gone; 24 independent cleanup queries and the released global
lock pass. The 305-entry attempt seal, including the account prerequisite probe,
has manifest SHA256
`c9c4ff316c5f738ba7e5afa87cfd43bd6b3985ef5f138eaa8e53c1a6c7bd711e`.

## Corrected account and session-option replay

All four profiles reach eight cases; each has one refused-port assertion
failure. All 20 real native/owner session proofs and remote closures complete,
including repeated owner Meterpreter and Bash sessions on root, named non-root
and versionless targets. Patched default and forced attempts create no owner
sessions. Unicode, quoted/backslash and configured-ident commands pass.

The module correctly returns reason-bearing Unknown, whose valid console text
is `Cannot reliably check exploitability.` The fixture had expected the separate
missing/invalid-CheckCode diagnostic. Correcting both negative-case assertions
checks the valid contract more precisely. The PostgreSQL case remains unrun in
this attempt. All 24 cleanup queries and the global lock release pass.
The 327-entry frozen attempt has manifest SHA256
`13cefb2705703bf4d0fa0aed6371f4d83d1589c725f1fbed80104e91f3e9e8f1`.

## Transient-parent observer refinement

At fixture revision `919ba0fa8ae`, root, named non-root and patched profiles each
pass all nine cases. Their independent artifact audit verifies the actual bytes,
all 14 native/owner session closures, the real PostgreSQL protocol rejection,
zero OOM/PID-limit events and unchanged production inputs. The versionless
profile stops before any owner call: native Meterpreter PID 446 is alive and
successfully used, while its short-lived parent PID 443 exits between ancestry
reads. The resulting nine reported failures inherit one before-all observer
error. All four stacks and all 24 cleanup queries complete cleanly. The complete
319-entry snapshot has manifest SHA256
`1fe1b8d9f7b4847e1a2fbb602cfa95fd43c5f66050ece8243ef69086ae957564`.

The refined observer retains the already-verified live payload status and
recognizes a parent confirmed absent during sampling. Existing unreadable paths
still fail, and every observed PID must be absent after remote shutdown.
Nine capped, read-only native controls verify live, absent and read-error
behavior across the exact root/non-root/fixed images and UIDs; no Framework
owner runs in those controls. This changes only observation. Production source,
network commands, session use and module options remain unchanged.

The three passing profiles retain their original frozen input records. A fresh
versionless replay with the refined observer passes all nine cases. Its
135-entry archive has manifest SHA256
`05fddf73510d4457f4f7bbb538c18cb88b99cd32d848d45e131a227856e5d221`.
The original serial controller exits 1 because of the preserved versionless
observer failure; the replacement versionless controller exits 0. Neither
controller's aggregate exit is substituted for the individual profile evidence.

## Final verification and limits

The recorded profiles create **12 owning-module sessions**: two Linux HTTPS-fetch
x64 staged Meterpreter and two Unix reverse-Bash sessions on each affected
profile. Eight additional native calibration sessions establish both delivery
families independently, including on the patched target. All **20 real sessions**
are used through their actual APIs, write exact nonce bytes, pass independent
target PID/UID/file checks, shut down remotely and have SQL closure records.
Repeated executions verify cleanup permits a second session. Native calibrations
do not inflate owning-module or functional-case counts.

Twenty-four positive owning generic-command files match exact bytes, covering
quotes, literal backslashes, Unicode and configured SSH_IDENT. Eight patched
negative command records verify file absence. Twenty-four independent native
preauthentication requests straddle every profile's owner calls, covering plain,
quoted and Unicode commands. Correct and wrong passwords and ordinary
authenticated execution verify daemon health before and after those requests.
The versionless profile returns Detected and uses explicit ForceExploit for
execution. The fixed profile opens no owning session, creates no owning command
file and records no vulnerability. Refused ports and a genuine PostgreSQL
endpoint return reason-bearing Unknown; the PostgreSQL server remains usable
and logs an invalid startup packet, proving that the negative request reached it.

Ten unique workspace vulnerability rows are checked across the affected profiles
(four root, four non-root, two versionless). Some arise from passive Appears or
AutoCheck reporting and do not independently prove execution. The separate nonce
and session proofs establish actual execution. Fixed, refused and unrelated
controls have no vulnerability records.

The qualification audit independently rehashes all 454 entries in the two final
runtime archives, checks every selected profile's frozen inputs and verifies
that the only shared-input difference is the ancestry observer. A separate
29-entry checkpoint seal references 18 preserved archives whose 2,526 entries
were independently rehashed. Its manifest SHA256 is
`d2a9bfef2db1256056ea81208037612675952f56a3b6afa43842c7760ffe3f8a`;
the local archive identifier is `erlang-ssh-qualified-checkpoint-20261115`.
It includes the qualification facts, source/spec snapshots, audit scripts,
focused-unit and lint results, native reader controls, inventory summary and
protected guide hashes. The human module guide and Scenarios remain unchanged.

Each stack has at most three containers: target (0.5 CPU, 384 MiB, 128 PIDs),
Framework (1 CPU, 768 MiB, 256 PIDs) and PostgreSQL (0.5 CPU, 256 MiB, 128 PIDs).
Memory-plus-swap limits equal memory limits. Stacks run serially; no OOM or
PID-limit events occur. All 24 independent cleanup queries for the selected
profiles pass, the global lock is released, and the final global container
inventory is empty. The preserved failed serial attempt adds six more cleanup
queries for its replaced versionless profile, all passing.

Recorded RSpec wall times are approximately 266, 243, 155 and 272 seconds in
table order, including native/session setup and excluding image preparation and
Compose cleanup. The primary focused unit suite passes 52 examples, seed 7721.
Strict lint and module tidy retain only the three baseline metadata offenses
listed above; changed fixture Ruby files have no new offenses. No full local
RSpec suite is run.

Runtime qualification covers linux/amd64 and the exact releases, account modes,
payload families and paths above. Older OTP branches, native ARM64, macOS,
Windows, arbitrary unmapped numeric UIDs and broader deployments remain untested.
Official image digests and application versions are pinned; installed OS package
versions are retained in build logs but are not snapshot-locked. The broader
feasible-module campaign remains open. No PR is created.
