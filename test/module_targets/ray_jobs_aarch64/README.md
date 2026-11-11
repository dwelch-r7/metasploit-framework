# Ray AArch64 job sessions

This selectable profile extends the [Ray job lab](../ray_jobs/README.md) and
covers the owner's Linux AArch64 target on the pinned Ray 2.6.3 application.
It retains the three-container, 1,856 MiB and 2.1 CPU serial budget.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_jobs_aarch64
```

A generated AArch64 command ELF must create an exact native marker first. Real
AArch64 Meterpreter and shell payloads then require independent launch, live
session use and normal shutdown before the owning module runs. Two owner cases
repeat those session paths twice each. Before/after native Ray tasks and SDK jobs,
terminal job records and explicit cleanup are required. Native execution can
use the host's existing binary-format support; this profile installs no emulator
or binfmt handler and requires no privileged container or host PID namespace.
A failed native calibration supplies no owning-module verdict.

The [validation report](../VERIFICATION-20261111-ray-jobs.md) records actual
results and distinguishes the architecture of the Ray application image from
that of the executed payload. Configuration alone is not qualification.
