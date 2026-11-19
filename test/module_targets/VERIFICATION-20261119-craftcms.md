# Native Craft CMS verification — 2026-11-19

The stock vulnerable profile passes twenty cases and stops its PHP session case
at an independently failing payload prerequisite. The Craft PHP owner is not
invoked on that path. The stock fixed profile passes all 21 cases.
This batch adds **no qualified campaign coverage**: totals remain **308 runtime
owners in covered paths, 635 qualified profiles and 4,599 historical functional
cases**. The broader goal remains active. No PR is created.

## Results and their limits

| Run | Examples/failures | Used and closed owner sessions | Interpretation |
| --- | --- | --- | --- |
| Final stock Craft 4.4.14 | 21/1 | 12 | Twenty cases pass; native PHP bootstrap fails before the PHP owner runs |
| Final stock Craft 4.4.15 | 21/0 | 0 | Genuine fixed-release refusals |
| Earlier explicit patched-runtime full matrix | 21/0 | 14 | Experimental runtime only, before the new prerequisite guard |
| First full public matrix with the new guard and patched runtime | 21/1 | 12 | Native PHP succeeds; a newly introduced five-second C2 idle timeout kills the owner session before proof |
| Corrected public PHP case, explicit patched runtime | 1/0 | 2 | Native calibration and first/repeat owner use and closure pass |

The final stock replay is `20261119T085511-4dc992`. It has no pending cases or
errors outside examples. All 95 declared input digests remain
unchanged. The latest corrected experimental replay is
`20261119T085212-5e1941`; its separate native handler session is excluded from the
two owner sessions. The unaffected twenty cases passed in the preceding full
public run; a new full patched matrix after the timeout correction is not claimed.

Reproduce using the [native profile guide](craftcms/README.md). A failing native
prerequisite must not be reported as a Craft module defect or a passing setup.
The optional runtime comparison records its exact loaded source and explicitly
sets `stock_qualification: false`.

## Genuine targets and independent controls

The profiles pin Craft 4.4.14 and 4.4.15, the official Craft nginx base, the
historical starter and Composer dependency locks. The actual installer,
controllers, authentication, PostgreSQL, PHP-FPM and ImageMagick perform the
work. The target runs as UID 82. Critical installed source hashes are verified.
The base supplies PHP 8.2.26, Imagick 3.7.0 and ImageMagick 7.1.1-32.
[Release provenance](craftcms/releases.json) records the references and hashes.

Seventeen independent controls pass before and after both final profiles. They
exercise ordinary Twig and database rendering, administrator login/dashboard
access, rejected credentials, captions, MSL/PHP execution and vulnerable/fixed
condition and multipart contrasts. The fixture explicitly selects an installed
DejaVu font through the supported ImageMagick font policy. Server master PIDs,
critical source bytes, database state and a pre-existing harmless MSL upload
must remain unchanged.

Before module verdicts, native Bash callbacks and real curl/wget transfers execute
known x86/x64 ELF bytes with exit status 42. Independent printf/bourne decoders
must produce the same executables. Owner session checks require actual file or
shell operations, UID/PID and executable hashes, real TCP state, persisted owner/
payload/workspace metadata and closed database timestamps. Linux callback
processes must exit; the PHP-FPM worker may survive after its callback closes.
The final stock SQL snapshot contains twelve closed owner rows and no native PHP
session row. All per-example native snapshots match their baselines.

## Two focused module repairs

The original two-step exploit loses its PHP temporary upload before the later
ImageMagick request. A genuine native same-request upload/write works. The source
repair processes the multipart upload in that request and verifies the generated
webshell using its own fresh token. Discovery and unavailable-response handling
also return useful failures without claiming an unsupported successful upload.

The original cleanup deletes unrelated PHP upload files. Cleanup now matches this
run's exact multipart wire bytes, including its fresh verification token, before
registering a surviving temporary upload. A harmless pre-existing MSL file remains
byte-identical through repeated command, shell and Meterpreter paths. Cleanup
continues through the parent API.

The corrected identical focused suite changes **38/15 to 38/0**, with no pending
cases or outside-example errors. Three inherited default-payload lint warnings
remain; they are the only module msftidy diagnostics. Changed test Ruby files pass syntax and RuboCop; shell syntax and the module-document checker also pass.
The existing motionEye root-target profile also passes 16/0 after the shared
native-helper extension; this regression adds no new campaign coverage. The
original 3,321-byte human Scenarios suffix remains byte-identical. No host or
Framework dependency is installed and the full RSpec suite is not run.

## PHP runtime investigation and contained failures

The installed `metasploit-payloads` 2.0.257 plaintext source has SHA256
`e031bea39090ccc1c3086474c971c00368006e9105aa198d783f94225b36740d`.
Independent native staged and inline delivery fail without using Craft's exploit.
A stream contract control shows an empty read on an open connection being treated
as retirement while a packet body is still outstanding. A stock native trace
closes during a 59,152-byte bootstrap request with 42,112 bytes unacknowledged and
no preceding handler close. This is consistent with premature partial-packet
retirement; a failed-source opcode trace was not captured.

The proposed exact-read patch passes all twelve PHP 8.2 stream controls, eleven
PHP 8.3 Socket controls and two additional routing controls. Generic channel reads
and HTTP paths remain unchanged. Its loaded source SHA256 is
`0817e293eaaa5f6837a125cfc8649b354c7e77f4b9e12ae0d83dd0d24d4e3244`.
The documented recipe is recreated from the installed stock reader and produces
that exact hash. The patch is an explicit test asset, not an automatic dependency
or installed-gem modification. No owning payload repository branch or PR is
published.

The public native PHP guard uses the real handler, exact filesystem bytes, live
TCP state and a separately closed SQL record. It rejects repeated pending
connections before readiness and leaves the owner verdict withheld. A twelve-
second native expiry and thirty-second owner expiry bound reconnect loops. The
owner's five-second HTTP request timeout is shorter than its fifteen-second C2
idle timeout, allowing the synchronous request to return before session use.

Failed attempts remain sealed and unqualified. Three guard prototypes expose
numeric versus string job IDs, the listener entry at the end of the job context,
and protected counter visibility. The corrected guard observes the actual
payload's counter without replacing registration or dispatch. A subsequent full
run exposes the too-short C2 idle timeout; the corrected affected PHP case passes.
Earlier HTTP bind selection, large console captures, upload cleanup and native
setup failures also retain their original evidence. Source/fixture failures and
the stock payload failure are classified separately.

## Ownership, resources and evidence

The final profiles run serially with at most two task-labelled containers. The
app uses 0.75 CPU, 768 MiB and 128 PIDs; PostgreSQL uses 0.25 CPU, 384 MiB and
128 PIDs. All 184 resource-event captures contain zero events.
All 10 recorded Docker objects are independently absent afterward;
the task namespace is empty and unrelated initial container IDs remain present.
Completed stacks are removed immediately. Unused task-created containers older
than one hour are also subject to removal, scoped to their namespace and recorded
ownership. Unrelated containers are preserved.

The final stock evidence is sealed as
`craftcms-functional-20261119T085510` with SHA256 manifest
`d29ce546090ef11d12d1749e3ee14169a2a6de22927320ae7aeff5052876b776`. The corrected PHP replay is sealed as
`craftcms-functional-20261119T085210`, manifest
`793a32f5f9d6315a62ecc7f1b3d471524d7e70f681b6654b2c45cdd5ddb3bcf7`.
The preceding full public timeout counterexample is sealed as
`craftcms-functional-20261119T083951`, manifest
`ba29f66a8bb7e403d5e8a7aef20f66c6ebfc53bc12d336459bb8000c0540e8da`.

Legacy crashing HTTP 502 targets, other operating systems, TLS/prefix deployments
and unlisted payload families remain unqualified. CI qualification is separate
from these local results. The next two Craft owners have source/primary-advisory
feasibility notes only, not runtime qualification.

## Self-review

**Summary:** Native targets, focused source repairs and a bounded prerequisite
guard provide reproducible evidence while preserving the stock PHP failure.

**What looks good:** Genuine native controls, actual session use and reporting,
repeat cleanup, explicit runtime provenance and scoped Docker ownership.

**Concerns:** Stock PHP bootstrap remains unqualified. The latest timeout
correction has a focused PHP replay; no new full patched matrix is claimed.
The inherited lint warnings and unlisted deployment limits remain disclosed.

**Suggestions:** Continue the valuable module queue and retain the isolated PHP
receive fix for separate payload-runtime review; do not increase stock coverage
from the experimental comparison.
