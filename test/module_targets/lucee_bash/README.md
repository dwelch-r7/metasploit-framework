# Lucee default Bash session acceptance target

```sh
MODULE_TARGET_NAMESPACE=lucee-session-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb lucee_bash
```

This profile retains the genuine pinned Lucee 5.3.7.43 image and native CFML
controls. Its existing Perl runtime runs the shared process observer; no target
interpreter is installed. Independent callback and stock payload/handler gates
precede the actual module. A capped disposable PostgreSQL service records real
session open and close rows.

The first owner attempt leaves TARGET and PAYLOAD at the observed console
defaults. The repeat reuses the same selected owner with AutoCheck disabled.
Both leave `AllowNoCleanup` at its normal default. Read-only method events
capture physical CFML source before execution, then the real FileDropper path
and independent file/directory absence before fixture cleanup. Session use,
PID birth identity, callback sockets, reporting and public shutdown APIs must
settle back to the original process set between attempts.

Run serially with an explicit namespace. At most two containers run: one
1-CPU/768-MiB Lucee application and one 0.2-CPU/128-MiB reporting database,
each with equal memory/swap limits and bounded PIDs. Ports publish on loopback.
Finished and failed stacks, including networks, are removed immediately.
Automated captures do not supply human module Scenarios.
