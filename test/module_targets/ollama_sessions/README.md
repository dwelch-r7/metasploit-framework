# Ollama default Meterpreter and FileDropper cleanup

```sh
MODULE_TARGET_NAMESPACE=ollama-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ollama_sessions
```

This separate profile reuses the [pinned Ollama 0.1.33 target and native
controls](../ollama_rce/README.md) and adds a disposable reporting database.
The command and fixed-release profiles keep their lighter one-container setup.
Only this two-container stack runs at a time: application 1 CPU/1024 MiB/128 PIDs,
database 0.2 CPU/128 MiB/64 PIDs, memory equals swap and ports publish on loopback.

Independent native loader, ordinary OCI registration, physical traversal and
genuine API runner controls precede session work. A native callback proves the
route, UID, PID and socket inode. The normal stock Linux x64 Meterpreter stager
from a real handler is wrapped with the existing Framework ELF helper, installed
with exact-byte verification and launched independently. It must produce a usable
session and close remotely before the actual owner is allowed to run.

The owner then runs twice on one selected module. The first invocation retains
the default target and payload; both retain `AllowNoCleanup=false`. Passive
traces compare the real generated library to its physical bytes before chat and
record the original FileDropper lifecycle. Library removal must happen through
FileDropper before fixture cleanup. Each live session must write a real UID-zero
proof, own its observed PID/birth/socket inode and original open SQL row, respond
to a fresh RPC and shut down through the public Meterpreter API. The original
SQL row must close and the full process set, jobs, sessions and callback/listener
state must return to baseline before the repeat.

No target helper exec or Docker healthcheck may run while the global preload is
armed. Physical library/preload reads use the resident observer over host HTTP.
Legacy session-proof helpers run only after resident evidence proves the preload
absent. Those proof files are explicitly recovered; that recovery is distinct
from automatic removal of the module's library. Registries and stacks are removed
on success, failure and interruption; follow [CAMPAIGN.md](../CAMPAIGN.md).

Other payload families, releases, nonroot deployments and alternative model
directories remain outside this profile. Automated captures do not replace
human-written module Scenarios. A native failure withholds the owner verdict.
