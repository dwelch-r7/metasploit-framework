# Native Craft CMS execution targets

The profiles use genuine Craft CMS, PHP-FPM, nginx, PostgreSQL and ImageMagick.
Qualification is **in progress**. Registration and an HTTP status alone do not
establish that a module works.

| Profile | Craft CMS | Expected unauthenticated primitive |
| --- | --- | --- |
| `craftcms` | 4.4.14 | Condition execution and same-request MSL file write |
| `craftcms_fixed` | 4.4.15 | Condition and multipart requests denied |

The [upstream advisory](https://github.com/craftcms/cms/security/advisories/GHSA-4w8r-3xrw-v25g)
identifies these affected/fixed releases. [releases.json](releases.json) records
source references, critical file hashes and dependency-lock hashes. The base image
and historical starter are pinned; Composer installs the checked-in locks.

With the existing Framework bundle, Docker Compose and NASM:

```sh
MODULE_TARGET_NAMESPACE=craft-dev \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb craftcms craftcms_fixed
```

Select one profile for a shorter run. The guarded runner owns the shared worktree
lock; do not add an outer lock. Profiles run serially with two containers: the app
is capped at 0.75 CPU, 768 MiB and 128 PIDs; PostgreSQL uses 0.25 CPU, 384 MiB and
128 PIDs. Craft and Framework have separate database roles/databases. Only random
loopback ports are published. Finished stacks and volumes are removed immediately.
Choose your own namespace and keep cleanup confined to its recorded objects.

## Independent controls

The actual upstream installer, controllers, authentication and database remain
responsible for CMS behavior. Native gates verify installed source hashes,
ordinary Twig rendering, a database-backed template, wrong-password rejection,
real administrator login/dashboard access, default-font captions, independent
MSL/PHP execution and the vulnerable/fixed condition and upload contrasts. They
repeat after module tests and compare stable application state.

Before the owner runs, native Bash callbacks, curl and wget transfers, and
printf/bourne decoding must execute known 32-bit or 64-bit ELF files with the
expected bytes, exit status and application UID. These controls use independent
delivery paths and remove only their own new files/directories.

The fixture explicitly supplies an installed DejaVu default font through
ImageMagick's supported font policy. Two on-demand FPM workers bound memory use.
Neither setting replaces application handlers. Native controls must pass before
interpreting a module failure.

A harmless pre-existing MSL upload is part of the baseline. Native rendering and
upload controls must work with it present. Session cleanup must preserve its
bytes. If a test changes the baseline, remaining examples are left pending for
investigation; that run cannot qualify the module.

## Functional scope and limits

Cases exercise all four command functions, PHP execution, automatic/disabled/
forced checks, default and supplied webshell names, exact quotes/percent bytes,
repeated use and genuine negative resources/connections. Session cases cover PHP
Meterpreter, Bash, Linux fetch, both Linux architectures and curl/wget/printf/
bourne droppers, with use, reporting and closure checks.

Command-only cases explicitly use `AllowNoCleanup` and operator cleanup of only
observed created webshell/proof paths. Session cases use the real cleanup API.
PHP Meterpreter runs in a reusable FPM worker: its callback must close, while the
ordinary server process may survive. Linux callback processes must exit.

The original two-step upload failed on this independently working target; the
same-request native write succeeded. Source repairs pass 38 focused tests. Native
pilots have exercised the command cases and used/closed Bash, Linux fetch, curl,
wget, printf and bourne sessions, including repeated execution and preservation
of a pre-existing PHP upload. The four-case dropper pilot passed with eight
sessions and native checks before/after. The complete fixed-release profile also
passed all 21 cases using the stock bundle. The complete vulnerable profile passed
all 21 cases, with 14 used/closed sessions, only in an explicit experimental PHP
runtime comparison. Stock vulnerable-profile qualification remains unfinished;
no campaign coverage totals have been added.

### PHP Meterpreter investigation

PHP Meterpreter is unqualified on this image. An owner session was used and
closed successfully, but a repeated staged session failed bootstrap. Independent
native PHP-file delivery with the real handler also failed readiness for both
staged and inline PHP Meterpreter, without invoking the Craft exploit. Treat
those failures as a payload/runtime investigation, not proof of a Craft defect.

A separate socket-pair control using the unchanged pinned
[PHP payload source](https://github.com/rapid7/metasploit-payloads/blob/914cd7b43b33d3fe651fe89ccebebac7be3c5ae7/php/meterpreter/meterpreter.php#L1603)
reproduces an empty-read/dispatch mismatch: a complete packet is handled, while
its header with the body withheld retires an open stream. A stock native trace
also closes during a 59,152-byte bootstrap request, with 42,112 bytes still
unacknowledged and no preceding handler close. This supports premature partial
packet retirement; a failed-source opcode trace was not captured. The first
encryption exchange had already succeeded, so later reconnect errors must not
be mistaken for the initial failure.

The investigation patch passes the focused stream and Socket-object controls,
real encrypted PHP bootstrap and the full module comparison. The Socket controls
use a separate existing PHP 8.3.28 image; the Craft target's PHP 8.2.26 image does
not load that extension. The patch is not applied by ordinary runs. Keep the PHP
session case: it runs last so other execution families can still be exercised.

Before that case, an independent native PHP file uses the real handler and must
provide a ready session, exact filesystem bytes under UID 82, a live callback and
a separate closed database record. Its session is excluded from owner counts.
Multiple pending connections without readiness stop this prerequisite promptly;
the native baseline and cleanup still run. A prerequisite failure leaves the
Craft PHP verdict withheld. The native control has a 12-second session expiry;
owner PHP sessions have a 30-second expiry as a second bound on reconnect loops.
Owner PHP requests use a five-second HTTP timeout and a fifteen-second C2 idle
timeout so the synchronous request returns before the test uses the session.

### Explicit experimental runtime comparison

This optional comparison tests the proposed receive fix, not the stock checkout's
PHP payload. It uses the existing gem's supported source reader and a per-run
Framework configuration override. The installed gem and project dependencies stay
unchanged. Provide only trusted PHP Meterpreter source through
`CRAFT_PHP_RUNTIME_SOURCE`; the exact loaded source is saved in the disposable
config and recorded with its SHA256 and `stock_qualification: false`.

For the investigated `metasploit-payloads` 2.0.257 source:

```sh
mkdir -p tmp/craft-php-runtime/php/meterpreter
bundle exec ruby -rmetasploit-payloads -rdigest -e '
  source = MetasploitPayloads.read("meterpreter", "meterpreter.php")
  expected = "e031bea39090ccc1c3086474c971c00368006e9105aa198d783f94225b36740d"
  abort "Different payload source; review the patch before proceeding" unless Digest::SHA256.hexdigest(source) == expected
  File.binwrite(ARGV.fetch(0), source)
' tmp/craft-php-runtime/php/meterpreter/meterpreter.php
patch -d tmp/craft-php-runtime -p1 < test/module_targets/craftcms/php_meterpreter_exact_read.patch
CRAFT_PHP_RUNTIME_SOURCE="$PWD/tmp/craft-php-runtime/php/meterpreter/meterpreter.php" \
  MODULE_TARGET_NAMESPACE=craft-dev \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb craftcms
```

The tested patched source SHA256 is
`0817e293eaaa5f6837a125cfc8649b354c7e77f4b9e12ae0d83dd0d24d4e3244`.
Use a fresh directory when recreating it; applying a patch twice is not a valid
comparison. An experimental pass must not qualify the stock bundle. Unset
`CRAFT_PHP_RUNTIME_SOURCE` for an ordinary run. Retry settings limit failed
connection attempts; they do not bound successful-connect/early-retire loops.
The native prerequisite and session expiries bound those paths. Retain a failed
run's evidence for investigation and teardown.

Legacy crashing HTTP 502 environments have focused coverage only. Other Unix
systems, TLS/prefix deployments and unlisted payloads remain unqualified. No
historical human-written module Scenarios are generated or replaced.
