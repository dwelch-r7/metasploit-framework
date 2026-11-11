# Ray CPU profile command injection

This profile extends the [genuine Ray job component](../ray_jobs/README.md),
with three containers, 1,856 MiB and 2.1 CPUs. It installs no dependency, changes
no Ray handler and requests no additional capability or host PID namespace.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_profiler
```

Before module calls, installed-source/core/SDK controls pass and independent
requests bind the discovered node's PID to the actual same-user dashboard agent.
Ordinary SVG profiling and a harmless exact command marker are recorded
separately: py-spy permission/dependency errors can coexist with command
substitution in the real API. Unexpected response shapes stop setup.
Independent live payload calibration precedes the corresponding owning sessions.
Checks, repeated command paths, AutoCheck and unrelated content are covered.
Explicit operator cleanup and container teardown preserve the module's documented
ARTIFACTS_ON_DISK contract; this is not a pristine-product claim.

A configured profile is not qualification. Preserve unexpected failures before
changing fixture assumptions or production module code. AArch64 owner sessions
and additional versions require their own profiles.
