# Ignition native target

The fixture uses the Vulhub image pinned to its Linux amd64 manifest, with
PHP 7.4.15, Laravel 8.26.1 and Ignition 2.5.1. Thirteen installed source hashes
pin the real dependencies, application bootstrap, routes and configuration.
The image's normal Apache service serves the unmodified Laravel application.
Startup creates the required writable log file owned by `www-data`.

Run with Framework's bundle and Docker Compose v2:

```sh
MODULE_TARGET_NAMESPACE=ignition-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ignition
```

The independent native control uses installed PHP classes and PHP's own PHAR
writer, rather than copying Framework's serialized chain or archive formatter.
It disarms the local destructor and requires proof absence after generation.
The actual Ignition API then clears the log, records encoded bytes, converts the
log into the exact generated archive and triggers it. Physical bytes and UID 33
gate every owner command. Only the archive-generation CLI disables
`phar.readonly`; the HTTP runtime and normal verification retain their defaults.

The profile checks the genuine version response, exact command bytes, automatic
and explicit log selection, same-console repeat execution with AutoCheck disabled,
and configured missing-log denial. Native source and resource checks bracket the
profile. An HTTP status alone does not establish execution; failed native
prerequisites withhold an owner verdict. Human Scenarios remain separate.
Successful owner commands must leave an empty log, checked without resetting it
before the repeat. The deliberate missing-log denial instead asserts its expected
application error log and retains that diagnostic until the fixture is removed.

One capped app container runs at a time: 1 CPU, 512 MiB memory/equal swap and
128 PIDs, with HTTP published only on loopback. Windows, other releases and
session payload families require separate qualification. The guarded runner
namespaces ownership, serializes heavy work and removes the container and
ephemeral network in ensure, including after failure or interruption. Do not
leave a finished stack running or use a shared default Compose project.
