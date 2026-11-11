# Ray native preparation

Native prerequisites and actual owner cases have separate results, recorded in
the [campaign checkpoint](../VERIFICATION-20261111-ray.md). Begin with one
genuine pinned Ray2.6.3 head and an unrelated
Apache service: two containers, 1,088 MiB and 1.1 CPUs in total. Framework is not
started. Containers use the campaign lock and are removed with their owned
networks after capture, including on prerequisite failures. Cached images stay.

```sh
DOCKER_CONTEXT=default nice -n 10 bundle exec ruby test/module_targets/ray/native_gate.rb --native
DOCKER_CONTEXT=default nice -n 10 bundle exec ruby test/module_targets/ray/native_gate.rb --native 2.8.1
```

The target runs the supported Ray CLI, one advertised CPU, an 80MiB object store
in 96MiB shared memory, and small BLAS pools. These declarations require actual
startup/resource verification; they do not establish that the budget fits.
Both HTTP APIs publish random loopback ports directly. Literal traversal paths
do not pass through a normalizing proxy. The internal network remains available
for a later isolated Framework role; the public bridge enables local probes.

Native prerequisites bind installed Python/Ray/commit/source identity to pinned
official sources, require genuine GCS/raylet/dashboard/agent processes and a
completed native Ray task, exercise SDK jobs twice with actual terminal state,
exact output, PID/UID and metadata deletion, and compare exact UTF8/empty file
responses and genuine missing-file refusal. Workload fixture paths are removed
explicitly. Native driver history and product log retention are recorded rather
than described as a pristine product state. CPU profiling/injection, log glob
traversal, owner checks, payload delivery and sessions require separate evidence.

The earlier source-only plan's missing-PID command-target hypothesis is rejected
on the current source: both command and stager paths already pass PID and IP.
No owner change is made from that hypothesis. The job version-check boundary
remains a hypothesis until native and unchanged-owner behavior are compared.

The gate reuses the existing native preparation's lock, bounded process runner,
capture and exact cleanup without modifying that shared implementation. It
supplies its own initialization, source scope, resource validation and native
controls. No dependency or application handler replacement is introduced.

The first native run (`20261111t070038-1c99bd`) verified the pinned installation,
real task and all three static file controls. The first SDK job's supervisor
worker died before starting its task. Container memory peaked at 543,617,024
bytes with zero cgroup memory-limit/OOM events; the cause remains unverified.
No Framework module ran. Both containers and networks were removed, confirmed
by eight independent root cleanup queries. The next diagnostic run preserves
Ray's internal log tails and PID counters before teardown at the same limits.

The diagnostic replay (`20261111t070702-d4ecaa`) hit `pids.peak=256`
and `pids.events max=11`; the supervisor logged failed `pthread_create`, a
thread resource error and SIGABRT. Memory-limit/OOM counters remained zero.
Ray's reporter also divided by zero under the fractional 0.9 CPU quota. The
corrected plan keeps 1,024MiB for Ray, raises its process/thread ceiling to
512, and gives it one CPU. Apache retains 64MiB and 0.1 CPU. No application
source, API or worker behavior is replaced.

The 2.8.1 comparison uses its own pinned image and twelve immutable official
source hashes with the same resource plan and controls. It probes actual file
access as well as core/jobs; the documented fixed-version claim remains
unverified until this control is observed. A blocked file read requires its own
classification before treating a failed native control as a module result.
Its first attempt (`20261111t071542-e6e09a`) exited before application startup
with `OSError: No space left on device` creating `/tmp/ray`. This is a Docker
storage failure: no native version behavior or owner outcome was observed.
Both containers/networks were removed and eight root cleanup queries passed.

The first [actual file-read owner profile](../ray_lfi/README.md) ran seven cases:
five passed, while quoted filenames failed with and without AutoCheck. Native
controls passed before and after. The server captured literal spaces in the
owner's request target and returned HTTP400. The filename encoding repair passes
eight isolated tests using the real HttpClient and Rex request serializer at a
stubbed transport boundary. Functional qualification requires complete exact-byte and repeated-read
assertions; see the campaign checkpoint for observed replays. No owner is
qualified from that failed baseline.
