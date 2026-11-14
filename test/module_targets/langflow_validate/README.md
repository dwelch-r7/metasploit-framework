# Langflow command validation

The first two profiles run the official Linux amd64 Langflow 1.7.3 backend, pinned by
image digest, with automatic login enabled and disabled respectively. They use
one worker and SQLite. Automatic login forces the built-in `langflow` account
and password; the protected profile uses `module-target-admin` and its local
fixture password. Native requests verify both choices. No AI provider is required.
The supported `LANGFLOW_LAZY_LOAD_COMPONENTS=true` setting reduces startup work;
validation still imports and executes its real implementation on demand. A
canary in the actual backend verifies that setting. The application
implementation and HTTP endpoints remain unchanged.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_validate langflow_validate_auth langflow_validate_newer
```

Langflow 1.7.3 has a bounded 240-second health allowance because native cold
startup took roughly 140 seconds under its resource cap. The default for other
profiles stays 120 seconds. Compose continues immediately once healthy. The
third profile checks exact commands and passive classification on genuine 1.8.4;
it does not qualify additional session families on that release.

Independent native controls verify the version, installed validation and login
source hashes, backend UID, anonymous denial, incorrect-password denial, valid
explicit login and the effective automatic-login policy. Benign code must work.
Both valid token routes append exact file bytes twice, once per request, and
remove those files. The flow registry must remain unchanged.

Public console cases exercise check, explicit credentials, absent and incorrect
credentials with automatic fallback where enabled, AutoCheck on/off, exact
commands, adapted Python shell and staged Meterpreter payloads with both fork
settings, refused ports and missing application paths. Each repeats without
another module selection. Session checks require a real ready event, remote
identity and file operations, exact database provenance, responsive backend,
closed transport and disappearance of the original PID/birth identity.
The complete target process set must return with no extra live or defunct child,
callback connection, Framework job or session.

Only three containers run at once: target 3,072 MiB/one CPU, Framework 768 MiB/one
CPU and reporting database 128 MiB/0.2 CPU. Swap equals memory, published ports
bind to localhost and the guard shares a lock across worktrees. Teardown removes
the complete Compose project and verifies the global container inventory.

Scope is the implemented validation path on this one-worker Linux target with
the exercised command payloads and authentication policies. Other releases,
platforms, URL prefixes, TLS and identity providers require separate evidence.
The vendor advisory lists no patched version; an upper affected-version entry
alone does not establish that later versions are safe. Consult the dated report
for actual results and limitations.
