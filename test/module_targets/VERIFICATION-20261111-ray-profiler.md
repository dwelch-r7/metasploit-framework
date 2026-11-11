# Ray CPU profile owner validation, 2026-11-11

The checkpoint is **189 qualified modules, 134 profiles and 1,488 functional
examples**. Static registration covers 191 sources, with 313 documented container
hints still pending review. Registration is not proof of passing, and the overall
campaign remains incomplete.

This follows the [Ray job checkpoint](VERIFICATION-20261111-ray-jobs.md).
The [CPU profile lab](ray_profiler/README.md) runs genuine pinned Ray 2.6.3,
unrelated Apache and the canonical Framework console. It reuses the existing
Ray source/core/SDK controls and payload/session controller. Three containers
cap the serial pipeline at 1,856 MiB and 2.1 CPUs. No new dependency, capability,
privileged container, host PID namespace or application patch is introduced.
The production module is unchanged.

## Native profiler restriction and actual injection

Installed Ray/build/source identity, a real scheduled task and genuine SDK jobs
must pass before module calls. The independent profiler control fetches real
node metadata and binds its agent PID to the actual UID 1000 dashboard-agent
process. It records py-spy's installed binary SHA256 and version, native request
bytes/status/body, and a harmless exact command marker through the genuine API.

Installed py-spy 0.3.14 returns HTTP 500 for ordinary SVG profiling: the actual
stderr reports permission denied while reading the process executable. The
original source tries passwordless sudo, but this container requests no extra
ptrace capability. That feature restriction is recorded rather than hidden.
A separate command-substitution request also returns HTTP 500, yet creates the
exact native marker as UID 1000. Execution precedes py-spy's later failure.
Both before/after native controls reproduce this distinction. An HTTP error
alone therefore does not establish that the injection failed.

These are real application requests; no response handler or profiler result is
simulated. Unexpected native response shapes fail setup. Independent payload
calibration must pass before the corresponding owning session family. The fetch
calibration uses the CPU owner's ordinary no-fork default, matching its source
rather than copying the job owner's different default.

## Completed x64/x86 owner run

Run `20261111T085317-2773db`, worker source
`ff03c91a4d8a9c5c8f74b14f3d18c1d050483f2a`, passed ten examples in 422.987608
seconds, with zero failures, pending or outside-example errors. Both native Ray
phases passed, including exact source identity, real task, two SDK jobs per
phase, static-serving controls and owned fixture/submission cleanup. Both native
profiler controls prove exact same-user command execution despite ordinary
profiling permission denial.

The owner covers repeated checks, exact command markers with default and
disabled AutoCheck, unrelated-service Unknown and automatic refusal, x64/x86
wget staging and command-fetch delivery. All five independent payload
calibrations and ten owning sessions were used and closed normally: x64 staged
Meterpreter, x86 staged Meterpreter, fetched x64 Meterpreter, x64 shell and x86
staged shell. Each owner path ran twice in the same service lifetime.

Every session must execute a proof, identify its actual PID/UID and owned TCP
socket, then close normally. Target PID, connections and Framework session
absence must pass before continuing. Native SDK submission state remains empty
across CPU-module calls; accepted job identifiers are not used as an RCE proof.
Operator cleanup of narrowly scoped paths is recorded. Product logs, driver
history and module-created artifacts can remain until container teardown; the
ARTIFACTS_ON_DISK module is not described as leaving a pristine filesystem.

Target peak memory was 602,533,888 bytes, process/thread peak 291, with zero
memory/PID-limit/OOM events. Root observed the genuine cold first console prompt,
isolated BOOT and two fresh metadata snapshots, with no manually supplied seed.
All 135 parent-run files were imported unchanged, and all 88 selected inputs
match current primary sources. Original paths, source revision, commands and
result bytes remain unchanged. Nine independent root queries verified the exact
three containers and two networks absent, project label inventories empty and
global containers empty. No task volumes were created.

The immutable 226-file evidence package has checksum-manifest SHA256
`b3121ea0a2741de27b467ba4d0a8a20ea15695d420adbd102fc4ab863588b6f7`.
The separate [AArch64 profile](ray_profiler_aarch64/README.md) requires its own
calibration and owning sessions before qualification. Broader versions and the
modern log owner remain pending. No PR is created.

## AArch64 owner and current checkpoint

Run `20261111T090134-43d681`, worker source `6996533fbbf`, passed two examples
in 198.805534 seconds, with zero failures, pending and outside-example errors.
Both native Ray phases, independent profiler marker controls and AArch64
Meterpreter/shell calibrations passed. Ordinary profiling again returned the
recorded permission error, while native command markers executed as UID 1000.
Both owning session paths ran twice, were used and closed normally, with target
PID/socket and Framework session absence verified for all four sessions.

The amd64 Ray application runs AArch64 payload ELFs through the host's existing
binary-format support. No emulator/handler was installed by this work. These
results do not establish native AArch64 host or image behavior. Target peak
memory was 574,185,472 bytes, process/thread peak 291, with zero memory/PID-limit
and OOM events. Root observed another genuinely cold prompt/isolated BOOT and
two fresh metadata snapshots in this separate invocation, without manual seeding.

All 79 parent-run files were imported unchanged; all 96 selected inputs match
current primary sources. Nine root queries again prove all three exact
containers and both networks absent, label inventories empty and global
containers empty. There are no task volumes. The immutable 178-file package has
checksum-manifest SHA256
`d455b5fbaa953c5dae4c32cc5a2f2561f3349049e4a4917c75307e8d57951dca`.

| Profile | Examples / failures | Duration | Current selected inputs |
| --- | --- | --- | --- |
| CPU profile x64/x86 | 10 / 0 | 422.987608 s | 88 |
| CPU profile AArch64 payloads | 2 / 0 | 198.805534 s | 96 |

Across both profiles, seven independent calibrations and fourteen owning
session lifecycles passed. All four declared targets have main-path evidence
on this exact Ray 2.6.3 image. The seven retained calibration ELF files match
their recorded SHA256 and expected machine fields (x86 3, x64 62, AArch64 183).
Both profiles retain the three-container, 1,856 MiB and 2.1 CPU budget.
This adds one qualified module, two profiles and twelve examples to the prior
188/132/1,476 checkpoint. Earlier compatibility reviews remain unchanged;
Druid JavaScript, WordPress administrator and Superset RCE profiles remain
excluded from passing totals.

Primary independently verified both selected-input maps, all twenty-one
calibration/owning lifecycle records, ELF identities, three-file Ruby syntax
and zero-offense RuboCop, Python AST, module documentation lint, local links,
and unchanged human Scenarios bytes. No full Framework suite was run.

The eleven-file read-only root review package has checksum-manifest SHA256
`fe7ff7f20f7b6b994acdda5c6ebbb6df5efcb7920b0fab5bb36d19a9fed83d9f`.

## Remaining scope

Ordinary native profiling remains permission-denied at the default container
capabilities. Its restriction does not prevent the verified injection/session
paths. A working native-profiler privilege variant, additional Ray releases,
custom base paths and native AArch64 hosts/images need separate evidence.
Pinned 2.8.1 source contains format validation and subprocess argument lists,
but source inspection alone does not qualify its native or owning refusal
behavior or establish the earliest fixed release. The modern dashboard-log
owner and the initiating cause of the earlier Ray startup-watchdog failure
remain pending. No PR is created.
