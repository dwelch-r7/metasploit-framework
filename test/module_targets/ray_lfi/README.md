# Ray static file owner

This profile uses the [genuine Ray lab](../ray/README.md)
at pinned version 2.6.3, unrelated Apache, and the canonical Framework console.
The serial budget is three containers, 1,856MiB and 2.1 CPUs. No listener or
privilege exception is needed for this file-read module.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_lfi
```

Before owner calls, independent controls verify installed sources, a scheduled
task, two SDK jobs and exact UTF8/reserved/empty/missing file responses. Eight short owner
cases cover the actual check, UTF8 content from a quoted path, empty and missing
files, reserved/UTF8 filename characters including a literal `%2f`, unrelated-service
check/automatic refusal, and execution without AutoCheck.
Successful reads repeat within the same service lifetime. A final native phase
checks fixture bytes, removes only owned paths, and repeats native workloads.
Internal logs, cgroup counters and raw responses remain with the run artifacts.

The [2.8.1 profile](../ray_lfi_281/README.md) separately verifies confined reads
and Safe/AutoCheck behavior. This 2.6.3 profile does not qualify other versions,
CPU profiling, log traversal, job execution owners or payload sessions.

Completed runs and known limits are recorded in the
[campaign checkpoint](../VERIFICATION-20261111-ray.md). A configured profile
and a successful native preflight alone do not establish owner qualification.
