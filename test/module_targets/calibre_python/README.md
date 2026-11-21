# Calibre explicit Linux Python Meterpreter target

```sh
MODULE_TARGET_NAMESPACE=calibre-python-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb calibre_python
```

This profile shares the genuine, pinned Calibre 7.14.0 application and seeded
book from [the command target](../calibre/README.md). Independent formatter and
HTTP command proofs run before session tests. A separate real TCP callback
records the normal interpreter version, UID and persistent process identity.

The normal `cmd/unix/python/meterpreter/reverse_tcp` payload must first work
outside the exploit, with its default fork setting. The owner then explicitly
selects Linux TARGET 1 and that payload, followed by a repeated execution
on the same console object. Every admitted session must create physical UID-1000
proof, expose its persistent PID/birth and open socket, and own an original
reporting row. Public Meterpreter shutdown must remove the process/socket,
close that row and restore the complete baseline.

This target adds one 128 MiB reporting database beside the existing 768 MiB
application; both are capped, namespaced and removed immediately by ensure
cleanup. Stacks run serially through the guarded runner's shared lock. Readiness
failure withholds the owner verdict. Automated output does not supply human
module Scenarios; Windows and other payload families remain separate coverage.

The first omitted-payload attempt exposed a harness assumption: the actual
console chooses a Linux HTTP fetch payload when switching to TARGET 1. Its
uncalibrated fetch listener then failed to bind. That frame is retained and
does not qualify default selection. [The fetch companion](../calibre_fetch/README.md)
tests that observed default with independent native readiness.
