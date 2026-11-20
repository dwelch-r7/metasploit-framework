# Langflow auto-login execution targets

These targets exercise `exploit/multi/http/langflow_unauth_rce_cve_2026_9198`
against the real digest-pinned Langflow 1.8.4 backend, with its installed Python
3.12.12 and UID 1000. They use no external AI provider or replacement endpoint.
Use the repository's Ruby/bundle, Python 3 and Docker Compose on the host.

The short session profile tests an independent staged Python handler, then the
module's actual default target/payload and a repeat on the same selected console
instance:

```sh
MODULE_TARGET_NAMESPACE="langflow-local-$$" bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_auto_login_default
```

Choose a namespace unique to your work. The guarded runner shares the heavy-work
lock across worktrees, labels explicitly named Compose projects and removes each
finished stack before starting another. Containers, ephemeral networks and volumes
are removed on success, failure or interruption. Framework runs on the host.

## Profiles

| Profile | Cases | Purpose |
| --- | ---: | --- |
| `langflow_auto_login_default` | 2 | Native staged handler, actual default session and repeat |
| `langflow_auto_login_enabled` | 2 | Version check, exact commands, quoting/Unicode/CRLF and reused selection with AutoCheck disabled |
| `langflow_auto_login_disabled` | 2 | Same version with auto-login disabled; native authenticated execution still works while the module cannot retrieve a token |
| `langflow_auto_login_sessions` | 8 | Four native controls and four repeated owner paths: staged, staged without forking, inline Meterpreter and Python command shell |

Case counts describe the suites, including the independent controls. Only real
runtime replays qualify a profile; pending or withheld cases do not pass. See
[the verification record](../VERIFICATION-20261120-langflow-auto-login.md) for
actual results, repairs, retained failures and scope limits.

```sh
MODULE_TARGET_NAMESPACE="langflow-local-$$" bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_auto_login_enabled langflow_auto_login_disabled langflow_auto_login_sessions
```

## Native prerequisites and assertions

The application extends the existing [Langflow image recipe](../langflow/compose.yaml).
Its real installation, package versions and authentication sources are checked;
the login/validation source hashes also match immutable upstream revision
`6cb87cca4c868cad096fc14139e73157740b7419` in [sources.json](sources.json).
The lab retains `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=false` and varies
`LANGFLOW_AUTO_LOGIN`. Fixture credentials are the isolated image recipe's
`module-target-admin` / `module-target-native-password`.

Independent requests verify wrong-password denial, correct authentication,
protected validation, exact native execution and unchanged flow IDs. Every owner
command first runs as identical bytes through an independent native validator
request. Command proofs must match exact file bytes and UID, then disappear.
Disabled auto-login must deny anonymous token retrieval while authenticated
execution continues to work. The module's version-only Appears result is not
proof that the anonymous chain is available in that configuration.

Session controls launch real cached Framework handler payloads outside the
vulnerable endpoint before dependent owner paths. Sessions must reach readiness,
perform public file/session API operations, match real persisted owner/payload/
workspace records, expose a live callback and permit HTTP health checks. Shutdown
must close the reporting row, restore the complete original process and TCP
baseline and remove proofs. A leftover zombie is a failure. Fork settings are
explicit between families so cached console options cannot change their meaning.

The inherited process verifier uses callback port 4492. A native handshake claims
that host port first and confirms UID, bytes, EOF and client exit. A busy port is
a setup failure; the fixtures do not stop another service to free it.

## Resources and limits

Command profiles use one application container capped at one CPU, 3072 MiB/equal
swap and 256 PIDs. Session profiles add the existing reporting PostgreSQL service
capped at 0.2 CPU, 128 MiB/equal swap and 64 PIDs. Published application/database
ports bind only to ephemeral loopback ports. The reporting database has a
non-internal route so the host console can reach its loopback publication;
all networks are task-owned and disposable.

Artifacts under `tmp/module-target-tests/<run>/` retain declared input hashes,
native observations, module calls, exact outputs, process identities, database
records and cleanup receipts. Existing human-written module Scenarios remain
unchanged. Other releases, fixed-release behavior, TLS, prefixes, external
authentication providers, architectures and untested Python/OS versions remain
unqualified.
