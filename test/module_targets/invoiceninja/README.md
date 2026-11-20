# Invoice Ninja native targets

This disposable fixture uses the official Invoice Ninja 5.10.10 image pinned to
its Linux amd64 manifest, PHP 8.2.21 and Laravel 11.15.0. The fixed-release
profile uses the genuine official 5.10.11 image, whose vulnerable route is removed. A pinned MariaDB 10.6.19
service supplies the MySQL-family database. The genuine image entrypoint restores
its packaged storage/public files; the fixture then runs the application's real
migrations, seeder and `ninja:create-account` command. No vendor source is patched.

With Framework's bundle and Docker Compose v2 available:

```sh
MODULE_TARGET_NAMESPACE=invoiceninja-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceninja
MODULE_TARGET_NAMESPACE=invoiceninja-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceninja_fixed
```

The native runtime verifies seventeen installed source hashes, the database and
account state, the real login/version response, and decryption of its XSRF cookie.
Before each owner command it creates ciphertext with the installed Laravel
serializer/encrypter and sends it through the genuine `/route/{hash}` handler.
Physical bytes and UID 1500 prove execution; the HTTP status alone does not.
A stock `php/exec` program also executes directly through the target PHP CLI
before its owner attempt, separating interpreter readiness from shell quoting.
The serializer cannot execute its proof in the generation process, and proof
absence before the HTTP request is checked separately.

The functional profile exercises the actual version check, both Unix and PHP
command targets, exact ASCII/Unicode/LF/CRLF/quoted bytes, key-file selection,
native and owner wrong-key denial and a second execution on the same selected module with
AutoCheck disabled. Source/database/resource checks bracket the profile. Failed
native prerequisites withhold an owner verdict. The fixed profile verifies the
removed route in the live router, healthy login and repeated native denial, then
requires Safe check output and normal AutoCheck withholding the owner payload.

Stacks run serially with at most two capped containers: 1 CPU/1024 MiB/128 PIDs
for the unprivileged app and 0.5 CPU/512 MiB/128 PIDs for MariaDB, with equal swap
limits. Only HTTP is published on loopback; the database uses an internal
network and an ephemeral project volume. Credentials and the published default
APP_KEY are disposable fixture values. The PHP CLI test server uses the real
Laravel router; nginx/FPM, other operating systems and other releases are outside
this profile's scope.

The guarded runner namespaces every project, labels ownership, serializes heavy
work and removes its containers, networks and ephemeral volumes in ensure,
including after failure or interruption. Do not leave finished stacks running or
use a shared Compose project. Follow the repository's container lifecycle policy.

Earlier feasibility runs are retained separately: SQLite migrations fail on
MySQL prefix-index syntax, and migrations without account creation leave login
unready. Those observations establish setup requirements, not module failures.
