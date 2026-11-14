# Langflow public-flow definition boundary

These profiles use official Linux amd64 Langflow 1.8.4 and 1.9.0 images pinned
by digest. Both require application login; the tested public build requests
have no authentication token. No model provider is required.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_public langflow_public_fixed
```

Independent native controls verify 41 installed source hashes on 1.8.4 and 42
on 1.9.0. A known public flow accepts supplied code on 1.8.4. Version 1.9.0
ignores supplied definitions and builds the stored flow; an authenticated build
still executes the supplied canary. The controls require complete build events,
a valid vertex, exact one-write UID 1000/GID 0 proofs and the expected Data
output. Missing cookies, private flows, unknown UUIDs and malformed IDs have
separate negative controls.

The native probe obtains component schemas from the genuine application API.
It creates one public and one private fixture flow, compares their complete
records throughout the run, deletes only those two flows and verifies the full
original registry is restored. The stored fixture has a finite, harmless output
method. Native payload files are removed after each proof. Application endpoints
and implementation remain unchanged.

Functional cases repeat on the same selected owner. The affected profile covers
check, exact commands with AutoCheck on/off, Python shell, staged Meterpreter
with both fork settings, private/unknown flow rejection, refused ports and a
missing application path. Sessions require real readiness, remote identity/file
proof, database provenance, live backend health, closure and exact restoration
of the complete original process set. The fixed profile covers Safe, normal
AutoCheck abort and forced or disabled-AutoCheck attempts that must not claim
payload execution when the supplied definition is ignored.

Only three containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory and published
ports bind to localhost. The guarded runner serializes worktrees and removes
each project before the next profile starts.

Scope is these one-worker Linux releases, a known public flow and the exercised
Python payload families. Other versions, platforms, replicas, TLS, providers and
stageless payloads require separate evidence. The independent native calibration
does not by itself qualify the Framework module.
