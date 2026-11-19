# Native motionEye verification — 2026-11-19

The final four-profile matrix passes **64/0** functional cases, with sixteen
used and closed sessions and twelve exact command proofs. It adds one execution
owner and four qualified profiles, reaching **308 runtime owners in covered
paths, 635 qualified profiles and 4,599 historical functional cases**. The broader
goal remains active. No PR is created.

## Final matrix

| Profile | Release | Authentication | Examples/failures | Used and closed sessions |
| --- | --- | --- | --- | --- |
| `motioneye_password` | 0.43.1b4 | Password | 16/0 | 8 |
| `motioneye_fixed` | 0.43.1 | Password | 16/0 | 0 |
| `motioneye_fixed_blank` | 0.43.1 | Blank | 16/0 | 0 |
| `motioneye` | 0.43.1b4 | Blank | 16/0 | 8 |

These results come from the same final serial replay, `20261119T045839-59f9c1`.
All 79 recorded input digests remain unchanged and match the tested files.
There are no pending examples or errors outside examples. Earlier successful
pilots do not inflate the qualified totals.

The cases cover checks, automatic/disabled/forced execution, repeated use,
quotes, dollars, percent conversions, rejected credentials and viewing-user
administration, absent paths and closed ports. Sessions cover Bash, x86/x64
stageless HTTP fetch and x64 staged HTTP fetch, including repeat execution.
Native shell, callback, HTTP and x86 executable controls run before owner tests.
Each session must perform real filesystem or shell operations, match its reported
owner/payload/workspace, persist in Framework and close. Native PID/UID, exact
proof bytes, matching delivered ELF hashes, sockets, channels and process removal
provide independent checks. All sixteen session records have closed timestamps.

Reproduce one release or the matrix using the
[native profile guide](motioneye/README.md).

## Provenance and independent controls

The original image is the documentation's official GHCR image, pinned to its
Linux AMD64 manifest and source revision `b005727d22521f32c44f0ae5531e5440735ffded`.
It installs motionEye 0.43.1b4. The fixed upstream 0.43.1 image is pinned to source
revision `358fb6df047a097e8670166635efa32ef6ad33de`. Image metadata and installed
source/entrypoint hashes are verified against those upstream revisions.
[releases.json](motioneye/releases.json) records the references and checksums.
No application handlers or owner methods are replaced.

The [upstream advisory](https://github.com/motioneye-project/motioneye/security/advisories/GHSA-j945-qm58-4gjx)
and [0.43.1b5 release](https://github.com/motioneye-project/motioneye/releases/tag/0.43.1b5)
identify the first fixed version. Native release coverage here is 0.43.1b4 and
the later 0.43.1; the b5 boundary also has focused semantic coverage, but no native
b5 image is claimed.

Sixteen independent native controls pass before and after every profile. They
verify installed sources, signed administrator requests, denied wrong/absent/
viewing-user credentials, actual camera configuration, genuine decoded testcard
snapshots, exact command writes or fixed-release refusals, and cleanup. Snapshots
must contain the generated red/blue pixels; HTTP200 and placeholder images alone
do not qualify. The original web processes, sources, credentials and control
camera configuration remain stable.

A separate working native camera calibrates ordinary media behavior. The actual
owner retains its generated dummy-camera requests; Faker is seeded to produce
loopback 127.235.216.81 and every request is checked. This contains generated
camera traffic without replacing its implementation. Independent session and
file proofs establish owner execution.

## Two focused source repairs

| Defect | Before/after evidence |
| --- | --- |
| Percent characters in command payloads are corrupted by Motion's filename/event formatting | The original real owner writes an epoch timestamp instead of motioneye-owner. Native contrasts show one/two percent signs yield timestamps, four preserve command bytes and eight yield literal %s. The same command regressions change 5/3 to 5/0. |
| Check crashes or raises on unavailable/missing pages and misclassifies fixed releases | The original owner dereferences nil on a real closed port, raises from check on native404, and reports source-verified fixed 0.43.1 as vulnerable. A reason-bearing Unknown contract and Rex::Version comparison against 0.43.1b5 correct these paths. The identical corrected combined suite changes 19/13 to 19/0. |

The percent fix is supported by the actual Motion 4.7.0 snapshot/event flow and
native command contrasts. The final combined suite contains **19 examples**,
including the five command examples; do not add 5+19 as separate final coverage.
Parent regression results are 19/0, with no pending or outside-example errors.
The native matrix independently replays both repairs.

Syntax checks pass and there are no new Ruby offenses. The owner retains one
inherited Style/HashExcept offense; msftidy exits 2 for that offense. The paired
module-document checker has no new diagnostics, established by running its
checks against original/current bytes with the same real module path. Its
historical singular Scenario heading, missing final newline, H2 ordering and
long line remain; the entire 3214-byte human Scenario suffix stays byte-identical.
No host or Framework dependency is installed and the full RSpec suite is not run.

## Preserved setup failures

All failed and corrected attempts remain evidence and are excluded from the
qualified totals. Native and Framework failures are classified separately:

| Setup or audit error | Correction and limit |
| --- | --- |
| An early native probe sends JSON Content-Type on empty GET requests and receives 500 | Send the header only with a body; actual authentication then passes and invalid credentials return 403. |
| Early HTTP-stream fixtures save placeholders | Use Motion's supported MJPEG decoder and verify actual source pixels. |
| Private JPEG exports copy lastsnap symlinks instead of their targets | Preserve the symlink metadata and native pixel measurements; exported image bytes are not claimed. |
| A mounted inspect.py shadows Python's standard-library inspect during initialization | Rename the mounted inspection tool; zero owner calls in the failed 16-case pilot. |
| Snapshot polling leaves an additional control-camera image | Wait for fresh file mtime after one acknowledged action; keep the exact state comparison. The failed run has 15/16 native controls and zero owner calls. |
| A copied independent audit expects the older ofbiz-session proof literal | Compare the recorded motioneye-session filesystem bytes; preserve the initial failed audit and unchanged raw runtime. |
| Password setup sends unwrapped settings to the bulk endpoint | Send the native main object. Both affected profiles stop before owner calls; the blank fixed profile passes on that earlier fixture. Replay all four after changing the shared helper. |
| An initial original-source AutoCheck unit reaches an unstubbed framework.db | Correct the unit fixture and rerun the identical corrected before/after pair; native fixed false-positive evidence remains independent. |
| A private documentation-baseline path appears to lack its module | Repeat the checker using original/current bytes with the same valid module path; do not compare that private-path exit2 with the real document's warning status. |

## Ownership and resource audit

The final matrix runs serially with at most two task-labelled containers. The app
uses 0.75 CPU, 512 MiB and 128 PIDs; its reporting database retains the shared smaller
limits. All 288 resource-event captures contain zero events. All 28 final
owned Docker objects are independently absent. Completed stacks are removed
immediately; unused task-created containers over one hour are also subject to
removal. Namespace labels, recorded IDs and exact Compose project ownership
scope cleanup. All unrelated IDs initially present in the final replay remain.

Camera configuration removal is verified separately from saved media. The
application retains stored-image directories, so fixture operator cleanup removes
only observed created paths and rejects baseline collisions. The final audit
records 72 existing media directories removed. This is not a claim that
the owner removes saved images itself.

All earlier task-owned prototype/pilot objects are also removed. During one
unqualified prototype, two unrelated MCP containers terminate before that
prototype's cleanup begins. Exact events and timing are retained; the initiating
actor is unknown. No task cleanup command targets either unrelated container, and this
is not recorded as a universal preservation result for that prototype.

Other Unix operating systems, application prefix deployments, literal multiline
configuration values and unlisted payload families remain unqualified. The next
Craft candidate has only static source/document review; no image or runtime
qualification is claimed. CI is reported separately from local native testing.

## Self-review

**Summary:** Four native profiles qualify the real command/session owner and two
focused repairs, with failed setups and original counterexamples preserved.

**What looks good:** Independent media, authentication and command controls;
actual session use and closure; exact shared inputs; owned Docker cleanup.

**Concerns:** Native b5 and unlisted platform/transport paths remain untested;
historical source/doc formatting diagnostics remain disclosed. CI qualification
is separate from these local results.

**Suggestions:** Continue the native feasibility queue, retaining primary
provenance and independently working application controls before module verdicts.
