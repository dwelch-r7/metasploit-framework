# Ray profiler AArch64 payloads

This separate profile extends the [CPU profile lab](../ray_profiler/README.md)
with the same three-container, 1,856 MiB and 2.1 CPU serial budget.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_profiler_aarch64
```

Independent native core/SDK controls, profiler request captures and an exact
command marker precede owner calls. A generated AArch64 command ELF and real
Meterpreter/shell calibration must work through existing host binary-format
support. Each owning session path then runs twice with actual use and normal
shutdown verified at the target PID/socket and Framework session boundaries.
No emulator, extra capability, host PID namespace or application patch is added.
The Ray image remains amd64; this does not establish native AArch64 host behavior.
Ordinary py-spy profiling can be denied independently of command substitution.
A configured profile alone is not qualification.
