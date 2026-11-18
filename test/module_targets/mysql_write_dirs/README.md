# Native MySQL directory write tests

These opt-in profiles test `auxiliary/scanner/mysql/mysql_writable_dirs` against
pinned official MySQL 8.0.36 and MariaDB 11.2.2, including MySQL's
`NO_BACKSLASH_ESCAPES` mode. Native clients independently prove exact four-byte
writes, OS/SQL permission failures, the secure-file boundary, collisions and
quoted/backslash paths before and after the real module.

```sh
MODULE_TARGET_NAMESPACE=my-write-tests bundle exec ruby tools/dev/run_guarded_module_target_tests.rb mysql_write_dirs mysql_write_dirs_mariadb mysql_write_dirs_nobackslash
```

The module intentionally leaves a file containing `test` in each writable
directory. Tests verify those actual bytes, paths, ownership and persisted notes,
then demonstrate collision behavior and a second successful execution after an
explicit lab reset. Cleanup removes only the test prefix in newly created lab
directories, after recording the module's real files, including incorrect paths.
This does not claim the module automatically cleans up its intentional artifacts.

Standalone and genuine MySQL-session paths are tested. Two capped containers run
serially with ephemeral loopback ports; completed projects are removed immediately
and unrelated containers are preserved. Public fixture accounts/passwords and
base SQL/filesystem controls reuse the [file-enumeration lab](../mysql_file_enum/README.md).
Each writer profile passes nine cases; all three file-enumeration regressions
pass eleven each. The [verification report](../VERIFICATION-20261118-mysql-write.md)
records the path repair, native controls, exact evidence and remaining limits.

Native requirements follow [SELECT INTO DUMPFILE](https://dev.mysql.com/doc/refman/8.0/en/select-into.html)
and [secure_file_priv](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv).
