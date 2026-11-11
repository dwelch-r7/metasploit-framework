# Ray 2.8.1 static boundary owner

This profile uses the [genuine Ray component](../ray/README.md) at pinned 2.8.1,
unrelated Apache and the canonical Framework console. Its three-role
budget is 2,112MiB/2.1CPUs; Ray uses 1,280MiB after the native supervisor
hit its memory threshold at 1,024MiB. [The affected 2.6.3 profile](../ray_lfi/README.md)
retains 1,856MiB/2.1CPUs. Ray's ordinary memory monitor remains enabled.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_lfi ray_lfi_281
```

The serial invocation allows normal metadata-cache reuse after a genuinely cold
first console. Native controls bind installed build/source identity, verify a
normal bundled static asset by exact hash, and require HTTP403 for all four
outside-file controls. A real task and two SDK jobs must succeed before owner
calls. The owner cases require Safe and default AutoCheck refusal, forced reads
of quoted/reserved/UTF8, empty and missing filenames to fail, and unrelated
content to remain Unknown. Forced reads repeat without reopening the service.
The final native phase verifies unchanged fixture bytes, removes owned paths
and repeats its workloads. Results and cleanup are retained with the run.

This static boundary result does not qualify the job execution, profiler or
modern log-traversal modules, other Ray versions, payloads or sessions. The
release image's actual build commit and release-tag comparison are recorded in
its manifest. Completed verification belongs in the campaign reports, not an
assumption that a configured profile passes.
