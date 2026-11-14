# Langflow legacy unauthenticated validation

These profiles run the real official Linux amd64 Langflow 1.4.2 image pinned by
digest, with automatic login enabled and disabled. The legacy authentication
path accepts requests without a key when automatic login is enabled. The
protected profile uses a configured active local account for independent native
controls; the unauthenticated module supplies no credentials.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_legacy_validation langflow_legacy_validation_protected
```

Keep the normal eager component loading (`LANGFLOW_LAZY_LOAD_COMPONENTS=false`).
Independent calibration found that lazy loading breaks this image's starter
project updater before any module call. Eager startup and both authentication
policies work without replacing endpoints or patching the application. No AI
provider is needed. The effective settings are read inside the actual backend.

Native controls verify installed package and source hashes, benign code,
invalid-token denial, exact repeated decorator/default-argument file writes,
file ownership and the complete flow registry. With automatic login disabled,
anonymous validation must return 403 while a valid token still executes those
controls. Populated default starter flows remain unchanged in the open profile.

Public console cases repeat check, exact commands, Python shell and staged
Meterpreter with both fork settings, AutoCheck on/off, refused ports and missing
paths. The protected profile tests denied commands without file creation and
denied payloads without sessions. Every case repeats on the same selected owner.
Session cases require real readiness, remote identity/file proof, exact database
provenance, live backend health, closure and complete process restoration.

Only three containers run at once: target 3,072 MiB/one CPU, Framework 768 MiB/one CPU
and database 128 MiB/0.2 CPU. Swap equals memory and published ports bind to
localhost. The guarded runner shares its lock across worktrees and removes the
whole project after each profile. PID, OOM and independent teardown checks
accompany the functional evidence.

Scope is this one-worker Linux 1.4.2 image, these authentication policies and the
exercised Python payloads. Other versions, platforms, providers, TLS and URL
prefixes require separate evidence. Passive version detection alone does not
prove that unauthenticated execution is allowed by the deployment's policy.
