# Lucee Linux x86 dropper acceptance target

```sh
MODULE_TARGET_NAMESPACE=lucee-dropper-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb lucee_dropper_x86
```

This profile shares the [x64 dropper controls](../lucee_dropper_x64/README.md)
while explicitly selecting `linux/x86/meterpreter/reverse_tcp` and Linux TARGET
1. Its independent stock ELF must prove native 32-bit execution and a complete
session lifecycle before the actual module runs. ELF class 1 and machine 3
are required; a native architecture failure withholds the owner verdict.

The actual owner repeats on the same selection, using normal command staging,
exact executable/transport bytes, physical CFML proof and automatic cleanup.
The same PID birth, socket ownership, reporting and baseline-restoration gates
apply. Resource caps, loopback ports, namespace requirements and immediate
container/network cleanup match the x64 profile. Automated captures do not
supply human module Scenarios.
