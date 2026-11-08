# PostgreSQL protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb postgres
```

This lab manages a pinned official PostgreSQL 16 image for the existing
`spec/acceptance/postgres_spec.rb` suite. Its health check uses a real authenticated
SQL query. The runner supplies its random loopback port through `POSTGRES_RPORT`.
Lab credentials are `postgres` / `password`.

The existing suite opens PostgreSQL sessions and exercises hash extraction,
version detection, file reading and SQL execution through session and direct-host
paths, plus `post/test/postgres`. Platform filtering or pending examples must be
investigated; they cannot silently count as a passing lab.

This first fixture covers one PostgreSQL version/configuration. Other versions,
restricted database roles, authentication modes and exploit modules remain in
the campaign queue. See [the shared guide](../README.md) for evidence and cleanup.
