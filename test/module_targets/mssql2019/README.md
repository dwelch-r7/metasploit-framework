# SQL Server 2019 protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mssql2019
```

This digest-pinned Microsoft SQL Server 2019 Linux image reuses the
[SQL Server 2022 lab's](../mssql2022/README.md) suite, public SA credential,
memory limits and native seed script. Running it accepts the image's EULA,
as in Framework's existing MSSQL acceptance workflow. Native sqlcmd must prove
authentication, the seeded row and the exact password hash before module checks.
Only a random host loopback port is published.

Both direct-host and session paths must extract that hash, discover the schema
and query the row. The two release families retain native authentication defaults.
Windows host operations, integrated authentication, restricted roles and
ARM/emulation remain unqualified. Native logs record the exact server build.

See [the shared guide](../README.md) for evidence and cleanup.
