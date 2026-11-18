# Backup Migration target

This target installs the unchanged official Backup Migration 1.3.7 or 1.3.8
archive into pinned WordPress 6.8.3 / PHP 8.3.28 / Apache and MariaDB 11.2.2.
The seed verifies the archive and every one of its 315 installed vendor files,
activates it as UID 33 and creates the existing synthetic WordPress accounts.

Prepare and run from the Framework root with the existing Ruby environment:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/backup_migration/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb backup_migration backup_migration_prefix backup_migration_fixed
```

The guarded launcher runs one two-container project at a time and removes its
containers, volumes and networks after each profile. Each container is capped
at 512 MiB, with equal swap limits, PID limits and CPU limits. Only the app's
HTTP port is published, on a random loopback port. Framework runs on the host;
the target must reach `host.docker.internal` for real reverse sessions. The
native UID-33 callback handshake determines a working host listener binding.

`native_control.py` independently proves real WordPress authentication, wrong
password rejection, vendor file integrity and the actual vulnerable endpoint
before and after the owner tests. It uses the captured, fixed filter chain in
`native-filter-chain.txt` for the readable PHP stub recorded alongside its hash
and pinned primary generator provenance in `native-filter-provenance.json`.
Regeneration uses that generator's literal conversion table, standard Base64
without padding, reversed characters and its documented filter ordering. It
does not load Framework's owner or filter helper. Generated header length is
6,839 bytes; Apache's header limits are unchanged. The vulnerable vendor endpoint
sends an incorrect Content-Length, so native proof requires exact marker bytes
and UID 33 even when HTTP reading ends with IncompleteRead. The patched release
must create no marker, including with valid complete path headers.

The functional suite exercises the actual check, sessionless command execution,
PHP stageless Meterpreter, Bash shell, Linux x64 HTTP fetch Meterpreter,
both AutoCheck modes, repeated runs, a missing base path, and the fixed version's AutoCheck refusal.
Real sessions write independently inspected proof files and close through their
public APIs. PHP Meterpreter can occupy an Apache worker; its PID is not killed
or required to disappear. Shell and Linux Mettle child processes and fetched
binaries must disappear. This does not qualify Windows execution, other PHP
versions, every payload or an exhaustive filesystem/process recovery claim.

The independent prerequisite run
`native-20261118t073316` passed both releases; earlier harness setup/login
assumption failures are preserved separately. No module repair is claimed.

The `backup_migration_staged` diagnostic is unqualified: staged PHP succeeded
once, then a cleanup-only replay repeatedly produced invalid sessions. Its
target showed zero OOM/PID limit events; the cause remains under investigation.
It is excluded from the three-profile command above and has a 120-second total
test bound. The original failures and stopped replay are retained. This is not
a confirmed owner defect. Run it separately when investigating:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb backup_migration_staged
```
