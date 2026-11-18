# Native MySQL schema metadata

These opt-in targets run official pinned MySQL 8.0.36 or MariaDB 11.2.2 with a
separate Framework reporting database. Fixtures use native SQL to create ordinary
and empty databases, a view, several column types, spaces/hyphens, reserved words
and escaped backticks in identifiers. Three SELECT/USAGE accounts expose different
native metadata visibility. User table rows contain a sentinel that must not
appear in a schema export.

```sh
MODULE_TARGET_NAMESPACE=my-schema-tests bundle exec ruby tools/dev/run_guarded_module_target_tests.rb mysql_schema mysql_schema_mariadb
```

Before and after module calls, vendor clients independently inspect each user's
visible schemas/tables/ordered column names and types, prove quoted identifiers
work and prove that the restricted account cannot inspect the extra schemas.
Expected metadata comes from native information-schema hex fields. Internal
`Daemon` entries such as MySQL 8's event scheduler are recorded separately from
client connections. Privileges/authentication caches are flushed before each
case, so the first standalone/session login is cold and its repeat is warm. These are real
objects and real permission boundaries, with no response handlers or parser stubs.

Tests use the actual `auxiliary/scanner/mysql/mysql_schemadump` entry point both
standalone and through genuine MySQL sessions created by the login module.
Existing-session cases must preserve the connection identity and remain usable.
MySQL 8.0.36 and MariaDB 11.2.2 each pass six cases, including strict repeat
checks for persisted notes and native metadata. The [verification report](../VERIFICATION-20261118-mysql-schema.md)
records the two confirmed repairs, sealed evidence and remaining limits.

The two containers are capped, ports bind ephemeral loopback addresses and the
shared guarded launcher serializes the stacks. Cleanup removes only the new task
project; unrelated containers are preserved. Public fixture credentials are
`schema_basic`, `schema_catalog` and `schema_none`, password
`Module-schema-password42!`. Root's lab password is `password`.
