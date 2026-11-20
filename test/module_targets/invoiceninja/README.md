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

## Real sessions

Run each session family in a fresh serialized stack:

```sh
MODULE_TARGET_NAMESPACE=invoiceninja-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceninja_bash
MODULE_TARGET_NAMESPACE=invoiceninja-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceninja_php_shell
MODULE_TARGET_NAMESPACE=invoiceninja-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceninja_fetch
MODULE_TARGET_NAMESPACE=invoiceninja-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceninja_php_staged
MODULE_TARGET_NAMESPACE=invoiceninja-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceninja_php_inline
```

The session app derives from the pinned official image and adds only the pinned
Alpine Bash package required by `reverse_bash`; app/vendor and payload sources
remain unchanged. The official image's missing-Bash native failure is retained as
a prerequisite failure. Installed package versions are recorded in each run.

These profiles add the existing 0.2 CPU/128 MiB/64 PID ephemeral PostgreSQL
reporting service, for a maximum of three capped containers. A native callback
proves host reachability and UID 1500. An independent stock handler session must
then pass real use, file/identity proof, original reporting-row closure and
PID/birth/socket baseline restoration before the owner is exercised twice.
Native readiness failure withholds owner execution and adds no qualification.

The fetch profile uses the image's existing curl, serves the stock Linux x64
Meterpreter payload, and verifies deletion of its downloaded file and closure of
the HTTP listener. Its first owner attempt selects target 1 and leaves PAYLOAD
unset; the actual selected payload must match the independent handler. The Bash
and PHP shell profiles select their target/payload explicitly. Every owner path
repeats on the same selected console object with AutoCheck disabled.

The PHP staged and inline Meterpreter profiles remain unqualified: their native
controls time out before a usable session, so owner execution is withheld. The
inline control also leaves a target socket after local cleanup; the runner
captures it and removes the entire stack. A staged owner attempt, if native
readiness passes, omits TARGET and PAYLOAD to exercise normal PHP defaults.
No private payload runtime patch or transport proxy is installed. Finished stacks,
including the reporting service and database volume, are immediately removed.

See the [session verification report](../VERIFICATION-20261120-invoiceninja-sessions.md)
for qualified paths and the separately retained prerequisite/readiness failures.
