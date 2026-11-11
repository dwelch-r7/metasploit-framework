# Ray job owner validation, 2026-11-11

The current checkpoint is **188 qualified modules, 132 lab profiles and 1,476
functional examples**. Static registration covers 190 sources; 314 documented
container hints remain pending review. Registration is not passing evidence.
The overall campaign remains incomplete, and no PR is created.

This record follows the [Ray file-read/version checkpoint](VERIFICATION-20261111-ray-281.md).
The [job profile](ray_jobs/README.md) runs genuine Ray 2.6.3 and unrelated Apache
with the canonical Framework console. Three containers cap the pipeline at
1,856 MiB and 2.1 CPUs. Only this serial pipeline may run; all containers are
removed after each attempt. The production job module is unchanged.

## Native controls and session evidence

Installed-source identity, a real scheduled task, two SDK jobs and static-serving
controls must pass before module calls. A direct agent-route control first proves
that `/api/jobs/` returns 404 on the agent port, then submits a real successful
job through `/api/job_agent/jobs/` and verifies exact target bytes, PID, UID and
logs. Owning submissions must reach SUCCEEDED; HTTP acceptance and printed job
identifiers alone are insufficient.

Independent payload calibration generates real ELFs through Framework, launches
them as UID 1000/GID 100, and uses actual handlers. Every session must execute a
target-side proof, identify its PID and owned socket, and close normally. Target
PID, connection and Framework session absence are required before proceeding.
The owning exploit repeats the same live-use/close checks twice per tested
payload path. Command markers, default/disabled AutoCheck, head/agent routes,
repeated checks and unrelated-service refusal are also exercised.

Owned submission metadata and narrowly scoped temporary files are explicitly
removed after examples. Repeats within one example retain the previous job
metadata. Native driver history, product logs and module-created artifacts can
persist until container teardown. This ARTIFACTS_ON_DISK module is not described
as leaving a pristine target.

## Preserved startup failure and recovery

Run `20261111T080436-c1b613`, source
`a2d86cb1097d3dc55adb172b781522e10fc8bd5f`, stopped in the shared native phase
before agent controls, payload calibration or owner calls. Nine before-all
failures therefore do not establish nine module defects. Raylet's agent logged
five consecutive missing-parent observations, exited through its watchdog,
and Raylet then stopped through fate-sharing. No memory/PID-limit event or
kernel OOM was observed. The initial reason for the missing-parent observations
remains unresolved.

Pinned Ray and psutil source suggest a mutable boot-time/create-time comparison
as one possible mechanism. A separately preserved source investigation does not
establish it as the cause. The later read-only sampler confirmed installed
psutil 5.9.5 and recorded 150 stable samples: no boot-time change and no missing
cached parent. It does not disprove a transient in the earlier attempt.

Docker's filesystem was nearly full. Exactly 154 old, unshared, reclaimable
build-cache IDs were selected for pruning; Docker reported 11 GB reclaimed.
All unique image IDs and volume names were unchanged. The later target observed
13,154,226,176 available bytes. The warning itself does not establish the cause
of Raylet's shutdown; no application patch, tmpfs workaround or monitor override
was used.

## Completed first owner run

Run `20261111T082018-8be919`, source
`2de12d6d38787a0e82e7cf5bfc95433abe6fdfbf`, returned nine examples, zero failures,
zero pending and zero outside-example errors in 226.945820 seconds. Both native
phases passed. Three independent payload calibrations and six owning session
lifecycles passed: staged x64 Meterpreter, command-fetch Meterpreter and x64
shell, each owner path executed twice.

The first actual prompt, isolated BOOT and two fresh metadata snapshots were
observed during the run. Nine independent root queries proved all three exact
container IDs and both network IDs absent, label inventories empty, and the
global all-container inventory empty. There are no task volumes.

| Evidence package | Files | SHA256 of checksum manifest |
| --- | --- | --- |
| Original native startup failure | 110 | `556fb88f1d4f53b4fe8c1f15d1d3dea17bd92a52f28e87896a96c6dc3f64f7c1` |
| Pinned parent-watchdog source analysis | 14 | `59b66ba13c1c99ae456ec59c6d2f048e8ee55c8f88276f2bdb3bd90ca54f8aff` |
| First nine-case owner success | 199 | `32f6b1c82af6d22092340911a552759becbcd930cf3bf34a3e7c8c79e3d34792` |

The original artifacts and selected source bytes were sealed before further
changes. Broader architectures, other Ray releases and the CPU/log owners are
not qualified by this first run. The complete campaign remains active.

## Expanded-run observer corrections

Run `20261111T082658-4367b6`, source
`4195708b329b9d694cb3b54f0d42d014a4c3cfcc`, returned eleven examples, one
failure and one outside-example error in 304.759668 seconds. All five independent
payload calibrations and ten owning session lifecycles passed, including staged
x86 Meterpreter and shell. It remains an unqualified full run.

The failed check expected the initial home-directory `ls` output as one contiguous
substring. Earlier fetch payloads legitimately added two files whose names sorted
between those baseline entries. Actual successful `ls` jobs returned the current
directory. The corrected assertion captures a fresh native listing before each
check and requires exact equality with every successful job's log bytes.

The outside-example error came from the diagnostic file-count guard: 228 genuine
Ray log files exceeded its 200-file bound. The final native result itself was
`native_passed`; diagnostic capture then failed. The shared helper now permits
512 files while retaining full-file hashes and at most 64 KiB of tail per file.
The affected file-read profiles require fresh replay after that shared change.

Nine root cleanup queries passed with an empty global container inventory.
The 224-file immutable package has checksum-manifest SHA256
`ce66603978508d5851ad710c8272429fba00197c5f4a3589473471dc9d97d578`.
This records two harness defects and does not establish a production module defect.

Both generated command controls executed successfully on the x86_64 LinuxKit
host: ELF machine 3 for x86 and 183 for AArch64, with exact marker bytes and
UID 1000/GID 100. Existing host binary-format support was sufficient; no emulator
or privileged-container configuration was installed. The separate
[AArch64 profile](ray_jobs_aarch64/README.md) still requires its own payload
calibration and owning session paths before qualification.

## Corrected x64/x86 owner replay

In batch `20261111T083443-a886ed`, source `349b74fa205`, the corrected main job
profile passed all eleven examples in 295.889959 seconds, with zero failures,
pending examples or outside-example errors. Both native phases passed. Five
independent payload calibrations and all ten owning sessions were used and
closed, covering x64 staged Meterpreter, command-fetch Meterpreter, x64 shell,
x86 staged Meterpreter and x86 staged shell. All owning paths ran twice.
The fresh exact-listing check passes regardless of earlier fetch files.

Final diagnostic capture retained 233 genuine Ray log records within the new
512-file bound. Target memory peak was 600,416,256 bytes, process/thread peak
292, and memory/PID-limit/OOM counters were zero. The refreshed 2.6.3 file-read
profile also passed eight cases in 59.626483 seconds on the changed diagnostic
source, with peak 575,516,672 bytes and no limit events.

The same batch's 2.8.1 native core task was killed by Ray's own memory monitor
at 1.19 GB out of 1.25 GB (fraction 0.954919, threshold 0.95). All eight owner
examples stopped in before-all setup. There were 1,446 memory-limit events,
no kernel OOM kills and a cgroup peak of 1,342,193,664 bytes. No 2.8.1 module
call was reached. The earlier successful 1,280 MiB run remains historical
evidence; it does not make that cap reliably sufficient.

## AArch64 owner and batch preservation

The separate AArch64 profile in the same batch passed two cases in 117.895013
seconds, with zero failures, pending or outside-example errors. Both independent
AArch64 payload calibrations and all four owning sessions executed a live proof
and closed normally. Both native Ray phases passed. These observations cover
payload execution through the host's existing binary-format support, while the
Ray application image remains amd64; they do not establish native AArch64 host
behavior or a different Ray image.

Across both job profiles, seven native payload calibrations and fourteen owning
session lifecycles passed. The four-profile manager exited one because the
2.8.1 native prerequisite failed. That aggregate exit does not overwrite the
three families' original passing results. Original paths, revision, commands
and result bytes remain unchanged.

Root observed the actual cold first prompt/BOOT and two fresh metadata snapshots.
Eight equality records verify the two JSON files across the first source/cache
and all three subsequent families' seed/configuration directories. Normal reuse
occurred only within that invocation; the first profile had no manual seed.
All 311 whole-parent files were imported byte-for-byte; the 43 file-read,
83 main-job and 91 AArch64 selected inputs match current primary sources.
Thirty-three independent root queries proved all twelve exact containers and
eight networks absent, four project label inventories empty, and global
containers empty. There are no task volumes. The immutable batch package has
417 files, checksum-manifest SHA256
`d6414216649e7fd1e56e0d3fa5b1fde98dbbeb94d55e6b117fd212d7b98346c4`.

The serial slot was released only after manager termination, root audit and
preservation. The follow-up changes only the 2.8.1 owner profile's target cap to
1,536 MiB (2,368 MiB total with Framework/Apache), retaining the memory monitor.
The standalone native launcher has its own separate resource plan; this owner
profile's cap and results do not requalify that plan.

## Ray 2.8.1 memory-headroom replay

Run `20261111T084452-32c5a8`, source `bbabb4a710f`, passed all eight examples in
61.089948 seconds, with zero failures, pending and outside-example errors.
Both native phases passed: installed source/build identity, real task, ordinary
static asset, all four HTTP403 outside-file controls, two successful SDK jobs
per phase, exact fixture preservation and owned-path/submission cleanup.
The actual owner returned Safe, refused automatic execution and rejected forced
file reads, including repeated quoted/reserved/UTF8 paths. The memory monitor
remained enabled. Peak memory was 1,306,923,008 bytes, process/thread peak 285,
and memory/PID-limit/OOM counters were zero.

Root observed the genuinely cold prompt/isolated BOOT and two fresh snapshots
again; this separate invocation reused no prior seed. All 62 parent-run files
were imported unchanged, with all 45 selected inputs current. Nine root queries
proved all three exact containers and both networks absent, label inventories
empty and global containers empty. The 110-file immutable package has
checksum-manifest SHA256
`196fa1430531f7b628ad730e411641d45f7d5e68ee650106b5109ed24d04ef7d`.

## Current qualification and remaining work

| Profile | Actual examples/failures | Duration | Selected inputs |
| --- | --- | --- | --- |
| Ray 2.6.3 file read | 8 / 0 | 59.626483 s | 43 |
| Ray 2.8.1 confined file read | 8 / 0 | 61.089948 s | 45 |
| Ray 2.6.3 x64/x86 jobs | 11 / 0 | 295.889959 s | 83 |
| Ray 2.6.3 AArch64 job payloads | 2 / 0 | 117.895013 s | 91 |

All four results have no pending examples or outside-example errors and passed
native controls and physical cleanup. The seven retained calibration ELFs were
independently checked against their recorded SHA256 and expected machine values:
x86 3, x64 62, AArch64 183. Main-job target peak was 600,416,256 bytes and AArch64
568,250,368 bytes, with no memory/PID-limit events. The serial container cap
stayed at three. The 2.8.1 owner profile now budgets 2,368 MiB total; the other
three budget 1,856 MiB each.

The source-bound checkpoint adds one qualified owner module, two profiles and
thirteen examples to the previous 187/130/1,463 checkpoint. The refreshed file
read profiles replace their earlier evidence rather than adding duplicate cases.
Previously documented default-network and unused-helper compatibility reviews
continue to apply to older campaign results. The Druid JavaScript, WordPress
administrator and Superset RCE owner profiles remain excluded from passing totals.

The Ray startup watchdog's initiating cause remains deferred. Other releases,
CPU profiling/injection, modern log traversal and genuine AArch64 host/image
behavior remain outside this qualification. In particular, successful native
2.8.1 SDK jobs do not settle the RCE owner's version gate without corresponding
module calls. [Deferred investigations](DEFERRED.md) retain that scope.

Primary independently verified all four current selected-input maps and 29
passing examples, seven retained ELF identities, syntax for all three changed
Ruby files, three-file RuboCop with zero offenses, both Python ASTs, module
documentation lint, local links and unchanged human Scenarios bytes. The
eleven-file read-only root review package has checksum-manifest SHA256
`b2586cd9dcc14adcfc7069be66288c2a32566c0916e61e990473834574c786fd`. No additional full Framework suite was run.
