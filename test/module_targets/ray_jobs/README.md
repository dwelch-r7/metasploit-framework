# Ray job execution owner

This profile exercises the genuine Ray job submission APIs.
It extends the [pinned Ray component](../ray/README.md) and adds unrelated Apache
and the canonical Framework console: three containers, 1,856MiB and 2.1CPUs.
Native SDK jobs and direct agent-route submission must pass before owner calls.
Module output that only reports an accepted submission is insufficient: jobs
must reach a genuine successful terminal state and target-side effects must be
observed. Real payload/session calibration precedes corresponding exploit paths.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_jobs
```

The profile records explicit operator cleanup of newly created target files;
it does not claim that an ARTIFACTS_ON_DISK module leaves a pristine filesystem.
Native driver history and product logs can persist. Only owned submission
records and narrowly scoped artifact paths are removed before a repeat.

The configured scope includes default/disabled AutoCheck, head/agent routes,
command markers, x64 wget staging, command-fetch payload delivery, real sessions
and unrelated-service negatives. Native x86/aarch64 execution remains a separate
architecture feasibility check. No job owner is qualified by preparation alone.
