# Native MySQL file and directory enumeration

These opt-in profiles run pinned official MySQL 8.0.36 or MariaDB 11.2.2 servers
and a real Framework reporting database. A third profile adds MySQL's
`NO_BACKSLASH_ESCAPES` mode. Native vendor SQL independently proves ordinary, empty,
nonnumeric, out-of-range, quoted and protected files, directories, missing paths,
SQL FILE privileges and the server's `secure_file_priv` boundary before and after
the collector. Files and permission controls are real; no responses are stubbed.

```sh
MODULE_TARGET_NAMESPACE=my-file-tests bundle exec ruby tools/dev/run_guarded_module_target_tests.rb mysql_file_enum mysql_file_enum_mariadb mysql_file_enum_nobackslash
```

Tests exercise `auxiliary/scanner/mysql/mysql_file_enum` standalone and through a
genuine MySQL session, with strict persisted-note comparisons and repeated calls.
The temporary table must be removed. The documented existing-table branch is
allowed to load rows, must retain that table and is explicitly reset between
executions. Borrowed sessions retain their connection and current user; the
collector selects its configured database using `USE`.

Two capped containers run serially with ephemeral loopback ports. Completed
projects are removed immediately; only resources created by the task are cleaned
up. Fixture users are `file_operator` and `no_file`, password
`Module-schema-password42!`; root's password is `password`. Server/session controls
reuse the existing MySQL schema lab helpers. The three file profiles pass 33 cases. The [verification report](../VERIFICATION-20261118-mysql-file-enum.md)
records the confirmed repairs, schema regressions, sealed evidence and limits.

Native prerequisites follow the official [LOAD DATA security requirements](https://dev.mysql.com/doc/refman/8.0/en/load-data.html)
and [secure_file_priv rules](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv).
