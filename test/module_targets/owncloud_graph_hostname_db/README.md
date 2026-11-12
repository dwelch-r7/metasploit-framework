# ownCloud hostname-only database configuration

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb owncloud_graph_hostname_db
```

This profile uses the [shared genuine ownCloud lab](../owncloud_phpinfo/README.md)
with `OWNCLOUD_DB_HOST=reporting_db`. No database port is supplied to the app.
It has the same four-container, 1,504 MiB/1.65 CPU limit and serial teardown.

The pinned vendor entrypoint expands this input to `reporting_db:5432` in the
running server's environment and ownCloud configuration. The module receives
that normalized value. This profile does not reproduce a captured database host
without a port or prove how another image handles provider defaults.

The normal native checks establish the fixture. An additional query through
ownCloud's own database connection, running as the web-service user, records
the actual server address/port, database and username. It also records the
application's configured host and libpq environment overrides. These observations
must precede the owning module's SQL persistence assertions. The actual connection
must agree with the observed startup normalization.

The query process copies PID 1's environment and drops to `www-data` before
bootstrapping ownCloud. A plain `docker compose exec` misses defaults exported
by the vendor entrypoint, including the database table prefix.

The single functional example repeats collection and verifies all four real
credential/service records, decoded fields, actual loot and deduplication.
Registration alone is not a passing result.
