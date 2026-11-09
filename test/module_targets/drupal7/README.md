# Drupal 7 Drupalgeddon 2

From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb drupal7 drupal7_php
```

This family exercises `exploit/unix/webapp/drupal_drupalgeddon2` against genuine
Drupal 7.57 and 7.58 installations. The [Drupal advisory](https://www.drupal.org/sa-core-2018-002)
identifies 7.0 through 7.57 as affected by CVE-2018-7600 and 7.58 as the fixing
release. The [fix](https://git.drupalcode.org/project/drupal/-/commit/2266d2a83db50e2f97682d9a0fb8a18e2722cba5)
adds request-key sanitization. Official release archives are pinned by their
published SHA-256 checksums:

| Release | Official archive SHA-256 |
| --- | --- |
| [7.57](https://www.drupal.org/project/drupal/releases/7.57) | `c3bc1173d7830941fa9ee6061d555fec334bd6834d2fc5c870f3aef1fbf667e2` |
| [7.58](https://www.drupal.org/project/drupal/releases/7.58) | `33d29980593477ab1504d21e4bf10455f6a386935a88b34ac6d14aaf94c42272` |

The runtime uses digest-pinned official PHP 5.6.40 Apache and MariaDB 11.2.2
images. GD and PDO MySQL are built using authenticated archived Debian Stretch
packages; the digest-pinned download stage supplies the current Debian archive
keyring. The libpng development package version is pinned. These historical
releases are test fixtures, with no current security recommendation implied.

Drupal's own noninteractive installer creates the standard profile, real
schema and administrator through installation forms. The bundled File module
provides the AJAX route used by this exploit. Five separate databases back a
root 7.57 installation, a `/drupal/` 7.57 installation, fixed 7.58, 7.57 with
assertions disabled, and 7.57 with its changelog withheld. Another genuine Apache
service is unrelated. Only random loopback HTTP ports are published. Fixture
mail goes to `/bin/true`; automatic Drupal cron and update checking are disabled.
The disposable administrator is `module_admin` / `module-target-password`.

Independent native controls bootstrap and inspect installed software, source
hashes, enabled modules, database driver and assertion policy. Real HTTP
requests verify anonymous password forms and denied administration. Fresh
target-side markers prove repeated PHP CLI and command execution as www-data
on vulnerable installations and its absence on 7.58. The request sequence is
derived from the [original Drupal 7 proof of concept](https://github.com/firefart/CVE-2018-7600/blob/master/poc.py),
using standard HTTP libraries and native Drupal forms. Native readiness retains
request bodies, replies, command statuses and cleanup evidence on failure.

PHP 5.6 `assert()` requires a string description as its second argument, while
Drupal 7's post-render callback passes the element array there. Native controls
record that refusal even with assertions enabled, and separately verify PHP CLI
execution. Session cases therefore exercise the module's existing CLI fallback
on this runtime. The assert-based in-process branch requires another compatible
runtime for qualification. No replacement callback or synthetic Drupal route
is installed.

Two independently bounded profiles retain 26 functional cases. `drupal7` has
19 check, command and native Linux session cases; `drupal7_php` has seven PHP
session cases. Either can also run alone. Each uses fresh application/database
state and repeats the full independent native preflight. Sequential execution
reuses only the canonical source-metadata snapshots described in the shared
guide; sessions and application state are never shared. This keeps each profile
within the runner's ten-minute bound, including a cold console bootstrap.

The cases cover check behavior, automatic and explicit Drupal 7
targets, fixed/unrelated/missing paths, missing changelog behavior, AutoCheck
disabled initialization, the configurable PHP command function, PHP shell and
staged Meterpreter sessions, and PHP/native Linux droppers. Successful state
changes repeat twice with fresh command proof and file-content cleanup checks.
The native preflight also exercises real callbacks to a standard Ruby listener
in the Framework container. A broken console stops the suite with a partial,
unqualified result instead of cascading later waits.

Inspect exact counts, inputs, native controls and resource teardown in each
run's artifacts using the [shared guide](../README.md). Drupal 8, other PHP or
database versions, TLS, authentication-gated core routes, contributed modules,
read-only webroots and the assert-based in-process branch remain outside this
family's qualification. Existing human module scenarios are preserved.
