# Drupal 7 Drupalgeddon 2

From the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  drupal7 drupal7_prefix drupal7_assert_off drupal7_no_changelog drupal7_fixed drupal7_unrelated \
  drupal7_php drupal7_php_staged drupal7_php_prefix drupal7_php_assert_off
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
provides the AJAX route used by this exploit. Each profile starts one selected
installation using its own database: root 7.57, a `/drupal/` 7.57 installation,
fixed 7.58, 7.57 with assertions disabled, or 7.57 with its changelog withheld.
The shared database initializer also creates the other empty lab databases. The unrelated profile uses a genuine Apache service and needs no database.
Only random loopback HTTP ports are published. Fixture mail goes to `/bin/true`; automatic Drupal cron and update checking are disabled.
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

Ten independently bounded profiles retain all 26 original functional cases.
The runner executes them sequentially and tears down each profile before the
next starts. Every profile contains one target and Framework, plus MariaDB when
Drupal is present. CPU, memory and PID limits apply to every service, with
`init: true`; the largest profile starts three containers. Application services
use 0.5 CPU, 384 MiB and 128 PIDs; MariaDB uses 0.5 CPU, 512 MiB and 128 PIDs;
Framework uses one CPU, 1536 MiB and 256 PIDs. Unrelated Apache uses 0.25 CPU,
128 MiB and 64 PIDs. Each run uses fresh application/database state and repeats
independent native controls for its actual role.

| Profile | Original cases | Selected target |
| --- | ---: | --- |
| `drupal7` | 7 | Root check, commands, missing path and Linux dropper |
| `drupal7_prefix` | 3 | Prefixed check, command and Linux dropper |
| `drupal7_assert_off` | 2 | Assertion-disabled check and Linux fallback |
| `drupal7_no_changelog` | 2 | Withheld changelog check and command |
| `drupal7_fixed` | 3 | Fixing release checks and refused execution |
| `drupal7_unrelated` | 2 | Unrelated Apache detection and refused execution |
| `drupal7_php` | 2 | Root PHP memory and dropper shells |
| `drupal7_php_staged` | 1 | Root staged PHP Meterpreter |
| `drupal7_php_prefix` | 2 | Prefixed PHP memory and dropper shells |
| `drupal7_php_assert_off` | 2 | Assertion-disabled PHP memory and dropper fallback |

Each profile can run alone. `profiles.rb` supplies the native service selection
and collection filter; the original acceptance cases, assertions, two-run loops
and cleanup helpers remain intact. The staged case is separate so a staging
failure does not consume the plain-shell profile's execution budget. Profile
registration and collection checks establish no new runtime qualification.

The cases cover check behavior, automatic and explicit Drupal 7
targets, fixed/unrelated/missing paths, missing changelog behavior, AutoCheck
disabled initialization, the configurable PHP command function, PHP shell and
staged Meterpreter sessions, and PHP/native Linux droppers. Successful state
changes repeat twice with fresh command proof and file-content cleanup checks.
The native preflight also exercises a real callback from each selected
vulnerable installation to a standard Ruby listener in the Framework container.
The fixed and unrelated profiles require zero callbacks. A broken console stops
the suite with a partial, unqualified result instead of cascading later waits.

Inspect exact counts, inputs, native controls and resource teardown in each
run's artifacts using the [shared guide](../README.md). Drupal 8, other PHP or
database versions, TLS, authentication-gated core routes, contributed modules,
read-only webroots and the assert-based in-process branch remain outside this
family's qualification. Existing human module scenarios are preserved.
