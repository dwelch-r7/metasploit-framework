# SQL Server 2022 protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mssql2022
```

This uses Microsoft's SQL Server 2022 Linux image pinned by digest, with the
Developer edition and the same public SA fixture credential used by Framework's
MSSQL acceptance workflow: `sa` / `yourStrong(!)Password`. Running it accepts the
image's EULA, as in that existing workflow. The container is limited to 3 GiB and
SQL Server to 2 GiB; allow this memory in Docker. Only a random host loopback port
is published.

Native `sqlcmd` authenticates and executes a query before Framework runs. It then
creates a small fixture database/table, reads its marker and independently
retrieves the SA password hash. The module must return that exact hash, discover
the real schema and query the seeded row over both supported paths. The
existing protocol suite exercises real MSSQL sessions and direct-host paths for
queries, hash extraction, version detection and schema/account enumeration,
including `post/test/mssql`. This Linux service cannot validate Windows host
exploitation or Windows-integrated authentication. The exact server build is
retained in the native logs and module output.

See [the shared guide](../README.md) for evidence and cleanup.
