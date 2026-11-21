# Lucee Linux x64 dropper acceptance target

```sh
MODULE_TARGET_NAMESPACE=lucee-dropper-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb lucee_dropper_x64
```

This profile retains the genuine pinned Lucee 5.3.7.43 image and the shared
native CFML, Perl process, callback and reporting controls. A stock independent
Linux x64 Meterpreter handler supplies the actual payload bytes. The existing
ELF generator wraps those bytes, native Base64 decoding installs them, and
physical source, UID, SHA256, ELF class and machine checks precede execution.
The independent session must work and close before any owner attempt.

The actual Linux TARGET 1 first uses the console-selected default payload,
then repeats on the same selected owner. The normal automatic stager selection
is preserved. Real executable and command-stager returns are captured, and the
Base64 commands must encode exactly that ELF and reach the real CFML executor.
The physical owner ELF and Base64 source must match those exact generated
bytes while the session is live, with the normal `MeterpreterTryToFork=false`
default. The fixture supplies a private writable directory and requires both
files absent and the directory empty after normal staging completes. Physical
CFML source and normal FileDropper removal are verified independently with
`AllowNoCleanup` left at false.

Both independent and owner sessions require exact proof bytes, original SQL
open/close rows, PID birth/socket ownership and complete process-set restoration.
The [x86 profile](../lucee_dropper_x86/README.md) separately gates that architecture.
At most two capped containers run: 1 CPU/768 MiB Lucee and 0.2 CPU/128 MiB
PostgreSQL, with equal memory/swap caps and bounded PIDs. Ports publish on
loopback. Use an explicit namespace and remove finished/failed stacks and
ephemeral networks immediately. Automated captures do not supply human Scenarios.
