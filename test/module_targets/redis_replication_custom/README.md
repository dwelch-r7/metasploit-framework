# Redis dynamically compiled extension qualification

Run from the repository root:

```sh
MODULE_TARGET_NAMESPACE=my-redis-custom-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb redis_replication_custom
```

This separate profile tests the default `CUSTOM=true` path on pinned Redis
5.0.14 x64/Alpine with the canonical Linux Framework compiler. The Framework
service copies the real SDK into a task-owned writable tmpfs; repository source
stays read-only. No target password is configured.

A separate C command proves compilation/loading and exact quoted Unicode/CRLF
file writes twice as UID 999. The real SDK template then embeds the stock
handler's already generated raw staged Meterpreter payload, with existing Linux
forking enabled. Its actual public session and physical PID/file/shutdown proof
must pass before owning calls. Native libraries and files are removed, module
state returns to baseline and jobs/sessions close.

The owning check precedes two executions leaving CUSTOM, TARGET and PAYLOAD
untouched; the second run reuses the selected console module. Compiler output and
the actual selected module/datastore prove the dynamic path ran. Generated
C/shared-library hashes are retained. Both owning
sessions must be used and closed and selected state restored after each run.
This profile is unqualified until its native controls and functional receipt pass.

Only a capped target/Framework pair runs, with namespaced immediate cleanup of
containers, anonymous volume and network on success or failure. The SDK tmpfs
disappears with Framework. Authentication, existing data preservation, native
replica/x86/other-release targets and explicit forking overrides remain separate.
