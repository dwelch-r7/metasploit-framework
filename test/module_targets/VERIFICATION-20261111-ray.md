# Ray module validation, 2026-11-11

The repaired `auxiliary/gather/ray_lfi_cve_2023_6020` is qualified on genuine
Ray2.6.3: eight functional cases passed in 61.872901 seconds, with no pending
examples or errors outside examples. Eleven public module calls include repeated
quoted/reserved/UTF8 filename reads, empty/missing files, unrelated content,
check and execution with AutoCheck disabled. Native controls passed before and
after; all containers/networks were removed and nine root cleanup queries passed.

The campaign checkpoint is now **187 qualified modules, 129 profiles and 1,455
functional examples**. Static registration is separate: 189 registered source
files out of 5,179 sources (4,622 module candidates, 555 payload components,
two supporting files), with 315 pending documented container hints. There are
15 individual feasibility reviews and no stale reviews. No PR is created.

Native application success remains separate from owning-module qualification.
[Run the profile](ray_lfi/README.md); [native component](ray/README.md).

## Reproducible target

The Ray component uses pinned official images, immutable source manifests,
the supported `ray start` command, a real control plane and SDK jobs. It does
not replace application handlers. The native gate uses two containers and the
file-read owner profile adds the canonical Framework console as a third.
Containers and owned networks are removed after every attempt; images remain
cached. Native controls and source identity must pass before module calls.

## Observed attempts

| Run | Source | Observed result |
| --- | --- | --- |
| Native 2.6.3 `20261111t070038-1c99bd` | `f6ac1a0de15` | Real task/static reads passed; native JobSupervisor died before executing a job. No owner calls. Cause initially unknown. |
| Native 2.6.3 `20261111t070702-d4ecaa` | `e17d31a6192` | Same limits reproduced worker failure. Internal logs show thread creation EAGAIN then SIGABRT; cgroup PID ceiling hit. No owner calls. |
| Native 2.6.3 `20261111t070814-73a323` | `2af1f27d73a` | Corrected limits passed installed identity, real task, two successful SDK jobs with exact output/PID/UID and deletion, plus exact UTF8/empty/missing file controls. No owner calls. |
| Native 2.8.1 `20261111t071542-e6e09a` | `114d1463cce` | Image pulled and pinned digest verified; CLI exited before application startup with Docker filesystem full creating `/tmp/ray`. No native control or module outcome. |
| Owner `20261111T071048-556399` | `52fe2d854d7` | Seven cases, five passed and two failed; native before/after passed. Literal spaces in the owner request caused actual HTTP400 for a quoted filename, with and without AutoCheck. |
| Repair `20261111T072204-aad961` | `15aa181fd60` | Eight cases, three harness matcher failures: actual file content was returned, but ASCII-8BIT console bytes were compared with UTF8 strings. Native before/after passed. Repeats were not completed, so this attempt did not qualify. |
| Final `20261111T072521-5ce915` | `dce661e9201` | Eight cases passed with binary byte assertions; all repeats completed. Native before/after passed, fixture bytes unchanged and owned paths removed. |

The diagnostic run reached `pids.peak=256`, `pids.events max=11`. The failed
supervisor logged `pthread_create` failures, a thread resource error and SIGABRT.
Memory-limit/OOM counters stayed zero, with memory peak 546,459,648 bytes. The
0.9 CPU quota also caused the reporter to divide by zero. The corrected Ray
limits are 1,024MiB, one CPU and 512 processes/threads; Apache uses 64MiB and
0.1 CPU. The passing native run peaked at 558,944,256 bytes and 291
processes/threads, with no memory or PID-limit events. No application patch or
privilege exception was used.

The owner baseline retained a genuine first prompt, its isolated BOOT path and
two fresh metadata snapshots (7,264 and two entries), with no manual seeding.
Native controls passed before and after owner cases. Five cases passed: genuine
check, empty file twice, missing-file failure, unrelated-service Unknown and
automatic refusal. The server log captured raw spaces in the request target
for the two failed cases. The independent native percent-encoded request returned
exact file bytes. This establishes a module path-encoding defect; it does not
qualify that baseline profile.

## Evidence and cleanup

Whole-run, selected-source and root-audit receipts were copied and verified
before any correction; the sealed files are read-only. Checksums identify each
local evidence package:

| Receipt | Files | SHA256 of checksum manifest | Root cleanup |
| --- | --- | --- | --- |
| First native failure | 90 | `8d6dd169b66e68c1faa88b5d25344a76da5ce1ef2e9fcc5e6f0114415c7a9d4b` | Eight queries passed |
| Native thread-limit diagnosis | 95 | `397b34dd00c6e3bcae037a0fad43ca02891e05ec30d2b7549eeb4f5114c64910` | Eight queries passed |
| Corrected native success | 93 | `0ad9d1fc3f12e3f6e31be711e3919b9ef82035dc29f7e0d0c56ba451db9ec851` | Eight queries passed |
| 2.8.1 storage failure | 79 | `b56dd2978bcd50dbc7a6bbcca79303e50186ee5e632323a09723d56b985cbc28` | Eight queries passed |
| Literal-space owner failure | 108 | `2cf2c57dd242889ee447c4e871c37d54f3c4f9b1cbcf844ace81b8b14f3137a4` | Nine queries passed |
| Repaired owner / harness matcher failure | 108 | `08db40dd3f00493e6e0e1347f526d4c6e94871ebd71071782f47182fdb865e53` | Nine queries passed |
| Final qualification | 122 | `ac3dbad6d4aa3ef3940fa3115a90e83b80a42b7ff08a01cfdf7043fa39637eb2` | Nine queries passed |
| Independent fix review | 7 | `c417a916ed595dcfec290deffe8d5e83cd3ca2e0141a2fc05eb6546303bbd340` | No Docker used |

The root audit checks collected container/network IDs directly, project labels,
and the global all-container inventory. There are no task volumes. An empty
label search alone is insufficient. The original failed run is preserved. The final whole parent run imported
62 files byte-for-byte into the primary checkout; all 43 selected inputs match
its current sources. The root separately compared all 19 changed code/lab/doc
files with the worker. Original absolute paths, results and commands remain
unaltered. The first prompt/BOOT and fresh metadata snapshots were retained;
root's cache audit read these artifacts after the manager terminated.

## Filename repair and storage recovery

The separate fix worktree committed `a4ae7be197cf9a44dc8c3a50a30faf4ace286f9d`,
integrated on the published campaign branch as `ac9748b479b`.
The module encodes the configured filename with the existing `Rex::Text.uri_encode`
helper before joining it to the unchanged literal traversal. Version gates and
other owner behavior are unchanged. Eight isolated examples use real HttpClient
path joining and Rex request serialization; connect/disconnect/send_recv are
stubbed. They cover ordinary paths, spaces/apostrophes, literal percent escapes,
fragment/query delimiters, UTF8, plus signs, an application subpath and input
immutability. The unchanged module failed six examples; the repair passed all
eight. Root independently reran the file: eight passed in 1.385979 seconds.
Primary independently reran the same eight examples: zero failures in
1.515919 seconds. Four changed Ruby files passed syntax checks, Python/JSON/shell
syntax passed, module documentation lint passed, and existing Scenarios bytes
are unchanged. RuboCop and msftidy retain only the pre-existing duplicate RPORT
option offense at line41; no new source/spec lint finding was introduced.
The final native Ray memory peak was 560,001,024 bytes, with process/thread peak
291 and zero memory/PID-limit events both before and after the owner cases.
The enforced three-role cap is 1,856MiB/2.1CPUs; native-only cap is 1,088MiB/1.1CPUs.

Docker reported 188.7GB of images, 47.24GB of build cache and zero containers
when the 2.8.1 CLI ran out of space. The host had ample space; Docker's overlay
filesystem was full. Exactly three unused, unshared campaign cache records for
Spark source archive downloads were pruned (301.1MB, 301MB, 231.8MB reported).
No image or volume was deleted. Two separately selected OpenTSDB cache prune
attempts reclaimed zero bytes and are not counted as freed space. A temporary
32MiB/0.1CPU storage probe exited zero and was removed; actual Docker events,
exact-ID absence and a fresh empty global container inventory were verified.
Its df output showed 468,048KiB available and ample free inodes. Storage remains
constrained; larger new image downloads need capacity planning.

## Remaining work

The filename repair and reserved-character replay are complete for Ray2.6.3.
Version boundaries, Ray job execution owners, CPU profiling/injection and modern log
traversal are not qualified by these native/file-read observations. The earlier
source plan's missing PID/IP hypothesis was rejected: both current CPU command
and stager branches already provide those arguments. No owner was changed from
that hypothesis.


The next Ray2.8.1 native comparison needs a verified writable target filesystem
before it can establish any version-boundary result. The official image pull is
cached, but the failed attempt supplied no native application evidence. The
three other Ray owners remain queued. The earlier Druid JavaScript, WordPress
admin and Superset RCE owner profiles also remain unqualified; this checkpoint
does not convert their failures into successes.

Read-only final review found the filename change focused and existing helper
reuse appropriate. Genuine controls, meaningful negatives and repeated reads
support the qualified 2.6.3 scope. Remaining concerns are version coverage,
Docker storage capacity and the existing duplicate RPORT lint finding.
