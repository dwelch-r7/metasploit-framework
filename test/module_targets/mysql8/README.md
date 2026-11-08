# MySQL 8 protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mysql8
```

This pinned Oracle MySQL 8.0.36 image uses its default authentication plugins
and provides a real target for `spec/acceptance/mysql_spec.rb`. The health check
makes an authenticated TCP SQL query. Lab credentials are `root` / `password`,
available only through a random published host loopback port.

The existing suite tests login/session creation, hashes, version, SQL and
enumeration through direct-host/session paths and `post/test/mysql`.
The assertions require hashes and account data for the configured user. Framework
credential persistence and downstream cracking are not verified without a
Framework database. Keep failures
unclassified until the target's account/plugin settings, native client behavior
and Framework output are inspected. Do not silently switch authentication
plugins to make a failing case pass. [MariaDB](../mariadb/README.md) is a separate
target. Other MySQL versions, TLS modes and restricted accounts remain to cover.
See [the shared guide](../README.md) for evidence and cleanup.
