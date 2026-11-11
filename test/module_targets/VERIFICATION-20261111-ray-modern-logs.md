# Modern Ray log enumeration validation, 2026-11-11

The checkpoint is **190 qualified modules, 135 lab profiles and 1,499 functional
examples**. Static registration covers 192 sources; 312 documented container
hints remain pending review. Registration is not proof of passing. The broader
campaign remains incomplete, and no PR is created.

The [owner profile](ray_logs_enum/README.md) qualifies genuine Ray 2.56.0 path
enumeration and loot on one Linux node. The module prints filesystem paths and
stores enumeration loot; it does not retrieve arbitrary file contents. Its
production source is unchanged. The [native component](ray_logs/README.md)
uses the normal Ray CLI, scheduler, dashboard subprocesses and log-agent gRPC
service, without replacing application handlers or adding privileges.

## Identity and independent controls

The official amd64 image is pinned to
`sha256:95ea9bc5d7f1ff9a5a8717e2ca92c987c9c27b6a08c57a930bf598150bdc7667`.
Its label and installed build commit match release tag
`637fd062205393b9e1929996bfe1d49bd3f8469d`. Eleven installed source files are
verified against immutable official hashes. A scheduled Ray task must actually
return 42 as UID 1000. Native SDK calls then enumerate nine controlled glob
patterns and retrieve the exact bytes of an owned ordinary log file.

Independent HTTP requests require the same actual paths for quoted/UTF8 names,
literal percent escapes, wildcard/literal question marks, directories, empty
files, missing globs and the module's `/etc/passw?` check. Ordinary in-log
listing/retrieval distinguishes a functioning service from a broken boundary
control. Cluster status must contain the genuine SDK node ID, and unrelated
Apache must reject the Ray API. Owned fixture bytes are verified and removed.
Driver history and product logs can remain until container teardown.

The [upstream fix](https://github.com/ray-project/ray/pull/64701) rejects absolute
or parent-directory glob components in the log agent. Ray 2.57.0's image/tag
metadata was inspected, but that image was not pulled or tested in this record.
No earliest-fixed-release or fixed-owner outcome is inferred from source alone.

## Preserved setup and probe failures

No Framework module ran during these native attempts. Each actual manager
terminated, then eight independent root queries proved the exact two containers,
two networks and project labels absent, with global containers empty. Failures
were sealed before changing selected inputs.

| Attempt / selected source | Observation | Receipt files / checksum-manifest SHA256 |
| --- | --- | --- |
| `091933-488591` / `dff5de10527` | Kernel OOM flag at 1,536 MiB during normal dashboard startup; native controls unreached. Exited-target cgroups/log exec unavailable. | 78 / `39a7e5eb764bdd0da5e72690dfd3e981c193984fbeef98acb1f666affb6eb38a` |
| `092402-c4155e` / `da0d57cb168` | At 3,072 MiB, no OOM flag; dashboard subprocesses fail thread creation under the inherited 512 ceiling. Read-only archive captures 41 internal logs. Cgroup counters unavailable after exit. | 86 / `ed46d19a4c9ec16cfaeb948f634efff984027bfc7a830e25865a192404898970` |
| `092730-87e826` / `c1ca363adae` | With 1,024 PID/thread slots, sampler sees 738 peak and no PID-limit events; memory peaks at 3,221,225,472 bytes with four kernel OOM kills. Native controls unreached. | 88 / `0d646b8093503a505bcc2ae235b864c32f3fd6e7fd767b39a729ff17cd20495b` |
| `093039-584d32` / `68ec1c22c45` | At 5,120 MiB/1,536 slots, startup, sources and real core task pass. Probe incorrectly supplies HTTP URL to State SDK bootstrap-address parameter. No resource-limit events. | 107 / `f4d365f5568be0b22e758c81ad3961bfbe9fe9ef97a772903c4caa5efec45356` |
| `093351-d33d2e` / `f9a623401b6` | Correct SDK `auto` address passes all nine SDK patterns and exact owned-log retrieval. Host probe incorrectly assumes an `internal` key for a successful empty result map. | 105 / `51fdfbb0ff33b68bf4d51ae0b73488c671cba05a61d3b2a4916af2a7c1ac10ea` |

These are resource/probe failures, not five module defects. The final empty-map
control requires HTTP 200, a true result flag and a dictionary; an absent
`internal` group means no matching paths. Positive cases still require their
exact known filesystem entries. Read-only startup samplers add one observed
process and do not import Ray or modify the application.

Host capacity was checked before the larger retry: 32 GiB RAM, 67% reported
free, with a 16 GiB Docker VM. Ray retains one CPU, a 5,120 MiB hard cap and
1,536 PID/thread slots. Those are limits, not reservations or claims of minimum
requirements. The full dashboard starts nine subprocess modules. Successful
native usage peaked at 3,913,089,024 bytes and 880 slots, with no limit events.

## Complete native baseline

Run `093641-d9e036`, source `70bf597eb6d9dcc28499f582e3391426464f1445`,
passes identity/source verification, the real task, nine SDK cases, exact owned
log bytes, eleven HTTP controls, unchanged fixtures and owned-path cleanup.
The manager exited zero, inputs stayed current and capture errors were empty.
Its immutable 100-file package has checksum-manifest SHA256
`e6d14a6ce58467ce98117377f539368877340adcf39ebe4d55bad667a3f040a8`.
A read-only root observer raced teardown; no simultaneous root-live observation
is claimed for that baseline. Its producer's resource snapshots and independent
root exact-resource cleanup are preserved. Native success alone adds no qualified
module or functional example.

## Owning module results

The first owner run `20261111T094313-2e7362`, source `3eedbf3348e`, passed all
eleven examples in 60.149075 seconds, with no failures, pending or outside-example
errors. It wrote fourteen exact new loot files; native controls passed before
and after. The resource observer's incorrect total (5,888 MiB) stopped that
observer, while the resolved runtime actually totaled 5,952 MiB. Root subsequently
verified the captured exact IDs, nine cleanup queries and genuine cold-console
artifacts. Its immutable 129-file package has checksum-manifest SHA256
`93aaadaa8918f54e30347c5311a054321d108cb2ca095733849d0ae028e87850`.
No simultaneous root-live/cold observation is claimed for that first run.

After correcting only the README arithmetic and read-only resource observer,
run `20261111T094736-69b984`, source
`277ddcfd6dbb100a8c8de02290cbce6c9f479b99`, passes all eleven examples in
68.947202 seconds, with zero failures, pending and outside-example errors.
The module covers:

- Repeated real traversal checks and automatic node discovery.
- Repeated outside-directory enumeration, directory suffixes and exact new loot.
- Explicit whitespace-trimmed node IDs and execution without AutoCheck.
- Quoted/UTF8 names, literal percent escapes, wildcard and literal question marks.
- Genuine empty files and ordinary log names.
- Missing-glob and unknown-node failures without invented loot.
- Unrelated-service Unknown and repeated automatic refusal.

All fourteen new loot files have the exact real node header and expected path
sets. An unmatched glob produces an empty API group map; the existing module
reports enumeration failure and creates no loot. No arbitrary file-content read
is claimed. Both before/after native phases and additional SDK checks of the
actual owner fixtures pass, with exact bytes unchanged and owned paths removed.
Target peak memory is 4,000,735,232 bytes and PID/thread peak 881; memory/PID-limit
and OOM event counters are zero. The serial owner budget is three containers,
5,952 MiB (5,120 Ray + 768 Framework + 64 Apache) and 2.1 CPUs.

Root observed only those three containers and the actual cold prompt, isolated
BOOT and two fresh metadata snapshots, with no manual seed. All 79 parent-run
files were imported unchanged; all 48 selected inputs match current primary
sources. Original paths, source revision, commands and result bytes are retained.
Nine root queries prove the exact three containers and two networks absent,
project label inventories empty and global containers empty. There are no task
volumes. The immutable final 130-file package has checksum-manifest SHA256
`34d666757b633739d783372e0df3fd4b3c6191945938cd02411e614a76d9e0de`.

## Remaining scope

This adds one qualified module, one profile and eleven examples to the previous
189/134/1,488 checkpoint. Earlier documented compatibility reviews remain
unchanged; Druid JavaScript, WordPress administrator and Superset RCE owner
profiles remain excluded from passing totals.

Multi-node grouping/partial failure, the fixed Ray comparison, other releases,
other host/image architectures, custom proxy/base paths and authentication modes
remain separate targets. The earlier Ray startup-watchdog cause remains deferred.
No production-module fix was needed for the verified single-node 2.56.0 scope.

Primary independently verified all 48 selected input hashes, the two native
source-byte maps (eleven files each), native SDK/owned-byte outcomes, three Ruby
syntax checks and zero-offense RuboCop, four Python ASTs, module documentation
lint, local links and unchanged human Scenarios bytes. The eight-file read-only
root review package has checksum-manifest SHA256
`5d5e3fbba57af004a3507884d49ec1a4f0b79c919b9f9a4f0757062e63dfbc14`. No full Framework suite was run.
