# Listmonk environment disclosure

Run stock, digest-pinned Listmonk 4.0.0, 5.0.1 and fixed 5.0.2 sequentially:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb listmonk_400 listmonk_501 listmonk_502
```

Each profile uses three containers: Listmonk (128 MiB, 0.25 CPU), PostgreSQL
(192 MiB, 0.2 CPU) and Framework (768 MiB, 1 CPU). PostgreSQL data lives in a
96 MiB tmpfs; no persistent or anonymous volume is created. The vendor entrypoint
installs the schema and sample list/template/campaign, bootstraps a disposable
administrator and runs the unmodified application as UID 1000. Nothing sends
email. No target source or API response is replaced.

The independent native probe uses form authentication, real APIs and SQL. It
verifies the binary and API versions, ordinary rendering, both `env` and
`expandenv` boundaries, invalid authentication, actual campaign permissions and
native campaign creation/deletion. A read-only campaign user can preview an
existing campaign and trigger the affected releases' bug, but cannot create or
delete one. The module currently creates a campaign and therefore requires
campaign management privileges; its read-only limitation is asserted explicitly.

Eight functional cases per version cover checks, all default variables, a fresh
per-run marker, HTML characters, Unicode, empty/unset values, explicit names,
restricted management privileges, read-only denial, bad credentials and a native
verified refused connection. Success/failure and named campaigns are repeated.
Loot must match independently read environment values exactly. Pre/post SQL
snapshots verify campaign, audience, template and authorization content; login
sessions/timestamps and advancing serial sequences are expected transient state.
Process identity must remain unchanged. The runner removes every owned container
and network on completion or failure.

Version/source identities are in [profiles.json](profiles.json). The affected
range and fix are documented by the
[vendor advisory](https://github.com/knadh/listmonk/security/advisories/GHSA-jc7g-x28f-3v3h).
The [5.0.1 installation](https://github.com/knadh/listmonk/blob/dc466fc76bde033d48af5fe89ffbd84bb7e194d3/docker-compose.yml)
documents environment bootstrap and schema installation. PostgreSQL 16 is the
repository's existing pinned image; native SQL and real preview controls verify
its compatibility with each selected application release.
