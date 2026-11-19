# Craft CMS image-transform targets

These profiles exercise `exploit/linux/http/craftcms_preauth_rce_cve_2025_32432`
against genuine Craft CMS, PHP-FPM, nginx, PostgreSQL and ImageMagick.
Qualification is in progress; registration alone is not a passing result.
See the [verification record](../VERIFICATION-20261119-craft-assets.md) for actual
results, retained failures and experimental-runtime limits.

| Profile | Craft CMS | Session storage | Expected image-transform behavior |
| --- | --- | --- | --- |
| `craftcms_assets` | 4.14.14 | Unset PHP path, actual `/tmp` | Fresh session inclusion executes |
| `craftcms_assets_session_path` | 4.14.14 | Explicit directory with spaces | Fresh session inclusion executes |
| `craftcms_assets_fixed` | 4.14.15 | Unset PHP path, actual `/tmp` | Object handles rejected; named transforms still work |

The [vendor advisory](https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3)
identifies the affected and fixed releases. [releases.json](releases.json) pins
source references, critical controller/bootstrap hashes and Composer locks.
The pair differs only in the CMS package; the 99 other locked package objects
are identical. The image reuses the pinned [Craft target](../craftcms/Dockerfile)
and the checked-in version-specific locks under `../craftcms/locks`.

With the existing Framework bundle, Docker Compose and NASM:

```sh
MODULE_TARGET_NAMESPACE=craft-assets-dev \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  craftcms_assets craftcms_assets_session_path craftcms_assets_fixed
```

Select one profile for a shorter run. The guarded runner owns the shared lock;
do not add an outer lock. Profiles run serially with at most three containers.
The app uses 0.75 CPU/768MiB/128 PIDs, PostgreSQL 0.25 CPU/384MiB/128 PIDs and
Framework 1 CPU/640MiB/128 PIDs. Only random loopback ports are published. Keep
cleanup within your namespace; completed stacks and volumes are removed promptly.

Native prerequisites create a real filesystem/volume through supported CMS APIs,
log in, upload a real PNG, read its exact bytes, and retrieve a named 6x4 transform
with exact pixels. They inspect FPM session configuration and actual new session
bytes, then exercise independent phpinfo and session inclusion or fixed rejection.
Seventeen ordinary CMS checks repeat before and after owner tests. Application
handlers and installed dependencies are unchanged.

The affected profile covers both targets, exact command bytes, automatic checks,
fresh disabled checks, repeat use of the same selection, a refused-port contrast,
Bash and inline x86/staged x64 fetch sessions, and staged PHP Meterpreter. Native
Bash, curl/wget ELF and PHP payload controls gate the corresponding owner paths.
Each owner session must be used, independently checked as UID 82, reported in SQL,
and closed. PHP runs in a reusable FPM worker: its callback must close while the
normal server process may survive. Other callback processes must exit.

The session-path and fixed profiles repeat the PHP and command cases. The
space-containing path profile also exercises explicit overrides with enabled and
disabled automatic checks and verifies that a missing override withholds the
command payload. Checks use
a fresh execution marker before accepting a session directory, including with
`AutoCheck` disabled. A failed proof is Unknown; a fixed target may also return
Unknown because this module does not identify the installed release passively.

Tests remove only newly observed owned session/proof files. They preserve existing
session hashes, uploaded assets and stable CMS state. OOM and PID-limit event counters must
remain zero. Historical module Scenarios are left unchanged. Craft 3.x/5.x, custom
session-cookie names, non-file session backends, TLS/prefix deployments and other
payloads remain outside these profiles.

## PHP prerequisite investigation

Stock PHP Meterpreter is not qualified. An independent native PHP file produced
a usable, closed session on this internal network, while a subsequent native
repetition failed readiness with repeated pending connections. The PHP Meterpreter owner path was
withheld in that failed run; both command targets and the Bash/Linux session
paths still passed.
Retain both outcomes. The earlier stock-runtime investigation is documented in
[the shared Craft targets](../craftcms/README.md#php-meterpreter-investigation).

The same explicit experimental source override described there is supported via
`CRAFT_PHP_RUNTIME_SOURCE`. It writes only the disposable Framework configuration
and records the exact loaded source/hash with `stock_qualification: false`.
A passing override run must not qualify the stock runtime. Ordinary runs keep the
native PHP prerequisite and fail if it cannot provide a real usable session.
