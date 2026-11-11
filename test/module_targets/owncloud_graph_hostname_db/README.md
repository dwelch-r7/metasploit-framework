# ownCloud hostname-only database configuration

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb owncloud_graph_hostname_db
```

This profile uses the [shared genuine ownCloud lab](../owncloud_phpinfo/README.md)
with `OWNCLOUD_DB_HOST=reporting_db`. No database port is supplied to the app.
It has the same four-container, 1,504 MiB/1.65 CPU limit and serial teardown.

The normal native checks establish the fixture. An additional query through
ownCloud's own database connection, running as the web-service user, records
the actual server address/port, database and username. It also records the
application's configured host and libpq environment overrides. These observations
must precede the owning module's SQL persistence assertions: a provider default
is not assumed merely because a hostname has no port.

The single functional example repeats collection and verifies all four real
credential/service records, decoded fields, actual loot and deduplication.
Registration alone is not a passing result.
