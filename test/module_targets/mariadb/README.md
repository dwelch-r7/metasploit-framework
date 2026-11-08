# MariaDB protocol suite target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mariadb
```

This pinned MariaDB 11.2.2 image provides a real target for the existing
`spec/acceptance/mysql_spec.rb` suite. The health check makes an authenticated
TCP SQL query. Lab credentials are `root` / `password`; the root account is
available remotely inside the disposable lab, with only a random host loopback
port published.

The suite tests login and session creation, hash extraction, version detection,
SQL queries and enumeration through direct-host and session paths, plus the
existing `post/test/mysql` module. Hash and account assertions require actual
values for the configured user, beyond a completion message. The hash module
reports through Framework's credential API despite its "Loot" console message;
this lab has no Framework database, so credential persistence/cracking are not
verified. It does not prove behavior on Oracle MySQL;
the [MySQL 8 fixture](../mysql8/README.md) uses that implementation separately.
See [the shared guide](../README.md) for evidence and cleanup.
