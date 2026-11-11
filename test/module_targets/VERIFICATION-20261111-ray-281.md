# Ray 2.8.1 boundary validation, 2026-11-11

The static-file owner now has verified affected and confined target profiles:
Ray 2.6.3 and the pinned official Ray 2.8.1 image. Both passed eight functional
cases, with native controls before and after. The shared control changes were
replayed against both targets. No module implementation or version gate changed
in this checkpoint, and no PR is created.

The campaign now has **187 qualified modules, 130 qualified profiles and 1,463
functional examples**. The new profile adds version coverage for an already
qualified module. Registration remains separate from qualification: 189 sources
are registered, with three generic profiles still unqualified (Druid JavaScript,
WordPress admin and Superset RCE). Other Ray owners remain unqualified.

## Reproduce

Follow the [2.8.1 profile](ray_lfi_281/README.md) or run both profiles serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_lfi ray_lfi_281
```

The first console starts cold. The runner normally reuses metadata within this
single invocation; there is no manual cache seeding. Both projects are removed
before the serial slot is released.

| Profile | Target / Apache / Framework caps | Functional result |
| --- | --- | --- |
| `ray_lfi` | 1,024 / 64 / 768 MiB; 2.1 CPUs combined | 8 passed in 60.067566s |
| `ray_lfi_281` | 1,280 / 64 / 768 MiB; 2.1 CPUs combined | 8 passed in 27.108398s |

At most three containers run. Native-only controls use two containers, capped
at 1,088 MiB for 2.6.3 or 1,344 MiB for 2.8.1 and 1.1 CPUs. Both use Linux/amd64
pinned images, installed Python 3.8.13, UID 1000/GID 100, one advertised Ray CPU,
a 96 MiB shared-memory cap and an 80 MiB object store. No privilege exception or
application-handler patch is used. Ray's normal memory monitor stays enabled.

## Native setup corrections and evidence

The earlier storage failure is retained in the [first Ray report](VERIFICATION-20261111-ray.md).
A fresh 64 MiB/0.1 CPU container using the actual 2.8.1 image wrote, fsynced, checked
and removed 9,500,000 bytes as UID 1000; it observed 478,695,424 bytes available before
writing. The probe exited zero and its exact container ID was removed. This
establishes a writable target filesystem before the native retry.

The image reports build commit `82a8df138fe7fcc5c42536ebf26e8c3665704fee`, while
the official release tag points at `3546c41b9996c36d0f1bba497dc660d3fcfc59a7`.
The official comparison contains three wheel-packaging commits and changes only
two wheel scripts. Twelve selected installed server-source files match both
commits byte-for-byte. The corrected manifest pins the actual build commit,
retains the release-tag identity and links the [official comparison](https://github.com/ray-project/ray/compare/82a8df138fe7fcc5c42536ebf26e8c3665704fee...3546c41b9996c36d0f1bba497dc660d3fcfc59a7).
The identity check remains strict; an observed commit was not accepted without
primary-source verification.

The first corrected-identity retry received HTTP 403 for traversal. Its old native
control assumed vulnerable behavior, so it stopped before SDK jobs. The revised
controls first fetch a real bundled static asset and compare its exact installed
hash, then require the profile's explicit traversal policy. On 2.8.1 the normal
430 byte asset returns HTTP 200, and all four outside paths return HTTP 403. This distinguishes
file confinement from a broken static server. On 2.6.3 the outside UTF8/reserved
and empty files return exact bytes, while the missing file returns HTTP 404.

At the old 1 GiB cap, Ray 2.8.1's own monitor killed the native job supervisor at
0.98 GiB usage against its 0.95 threshold. The cgroup peak reached 1,073,741,824 bytes,
with two memory-limit events and no kernel OOM kills. This was a target resource
failure, not an owner-module failure. Raising only 2.8.1 to 1,280 MiB allowed the
same native task and two SDK jobs to complete, with exact markers, PID/UID/logs
and removal of owned submission records/files. It did not disable the monitor.

| Native attempt | Outcome | Read-only receipt files / checksum manifest SHA256 |
| --- | --- | --- |
| `20261111t073150-02c64c` | Build identity mismatch; twelve source files match; no module calls | 97 / `3d8cfc679c356900258bfe5809bbe5817464d767161d863b9fb6765dc7c5789a` |
| `20261111t073352-052641` | Identity/core passed, HTTP 403 contradicted the vulnerable-only control; no module calls | 100 / `cd9041bd1c75ec73ff72b757abbe111ee7f2e423cacdda930afd444561c196f0` |
| `20261111t073659-67718b` | Ordinary static/hash and four confined controls passed; SDK job killed by memory monitor | 96 / `d95a91af36455969f88a4d2c63b1dca1bffb6980a89ef9487e8f500f320998d4` |
| `20261111t074003-7bbb14` | All native controls and both SDK jobs passed at 1,280 MiB | 96 / `4de7ed2653a6d20857be5738f99096d73df2b1e66299705a93c4dcf504409a84` |

Each native attempt independently passed eight root cleanup queries for its
collected two container IDs, two network IDs, project labels and global empty
container inventory. Failures were preserved before changing selected sources.

## Final owner batch

Run `20261111T074116-94a91d` used worker revision `5ed48ca903af9fe5d2f5337ca7f784635d470190`.
Both families returned 8/0/0/0 for examples/failures/pending/outside-example errors.
The 2.6.3 owner checks Vulnerable and reads exact fixture content, including
spaces, quotes, reserved characters, a literal percent escape and UTF8 names;
empty-file handling and genuine missing-file failure also pass. The 2.8.1 owner
checks Safe, honors default AutoCheck refusal, and rejects forced reads without
printing fixture content. Repeated reads/refusals and unrelated Apache checks
are included. Actual owner-nonce request logs independently show seven HTTP 200 and
one HTTP 404 on 2.6.3, and seven HTTP 403 on 2.8.1; failures are not merely generic parser errors (HTTP 400).

All four before/after native phases passed installed identity, real task,
ordinary static/hash and boundary controls, and two SDK jobs each (eight total).
Fixture bytes stayed unchanged and owned paths/submission records were removed.
Native driver history and product logs can persist; no pristine-product claim
is made. Target memory peaks were 559,046,656 bytes on 2.6.3 and 1,224,994,816 bytes
on 2.8.1, with no memory/PID-limit events. PID peaks were 292 and 288 respectively.

The first actual prompt, isolated BOOT and fresh snapshots (7,264 and two entries)
were retained. The second console's seed files equal the first source, shared
cache and second configuration byte-for-byte. All 119 parent-run files were
imported unchanged; all 43 selected 2.6.3 inputs and 45 selected 2.8.1 inputs match
current primary sources. Original absolute paths, commands and results remain
unaltered. Root also compared the 14 changed code/lab/doc files with the worker.
Changed Ruby lint and syntax, Python/JSON syntax, resolved Compose limits and
module documentation lint pass; human Scenarios bytes are unchanged.

The final read-only evidence package contains 184 files and has checksum-manifest SHA256
`57c3cea2411ad6690955ea1a3e6348040c54ae2da14461b8e78791a3587b1a30`.
Seventeen independent root queries proved all six collected containers and four
networks absent, both project label inventories empty and global containers empty.
There are no task volumes. The serial slot was released only after this audit.

## Review and remaining scope

The control changes separate a functioning static server, actual traversal,
confinement, native workload health and owning-module behavior. Explicit
version selection and strict build/source checks support this two-image scope.
No new concern remains within it. These results do not establish every 2.8.1
installation or the minimum fixed Ray release; intermediate versions and other
dependency builds need separate targets. The job execution, CPU profiler and
modern log-traversal owners still need their own main-path tests. Successful
SDK jobs are independent native evidence, not qualification of the RCE module.
Docker storage remains tight, so larger image additions need capacity review.
