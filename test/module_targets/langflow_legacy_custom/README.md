# Langflow legacy custom component execution

These profiles use the official Linux amd64 Langflow 1.3.2 image pinned by
digest, with automatic login enabled and disabled. They exercise the real
`/api/v1/custom_component` endpoint without an AI provider. The protected profile
uses an active local account for independent native controls; the owner module
supplies no credentials.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_legacy_custom langflow_legacy_custom_protected
```

The target uses normal eager component loading and a single backend worker.
Independent controls verify installed packages and source hashes, a benign
component with and without an empty frontend node, invalid-token rejection,
actual backend settings and builtin names, exact file writes and the complete
flow registry. A computed display name in the actual HTTP response must match
the backend PID independently written by the component. The native component
loader evaluates a decorator three times
across fresh scopes even when its source contains a local one-shot guard.
Those controls record and check all three writes. With automatic login disabled,
anonymous requests must return 403 while authenticated native controls still
execute.

Public console cases repeat the version check, exact command writes, Python
shell and staged Meterpreter with both fork settings, AutoCheck on/off, refused
ports and missing paths. The protected profile checks denied commands without
file creation and denied payloads without sessions. Each case repeats on the
same selected owner. Successful session cases require real readiness, remote
identity and file proof, database provenance, live backend health, closure and
complete process restoration. Native builtin and flow snapshots must match
before and after the owner cases.

Only three containers run at once: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory and published
ports bind to localhost. The guarded runner shares its lock across worktrees
and removes the project after each profile.

Scope is the pinned one-worker Linux image, these authentication policies and
the exercised Python payloads. Other versions, platforms, replicas, TLS and URL
prefixes require separate evidence. Passive version detection alone does not
prove that a deployment permits unauthenticated execution.
