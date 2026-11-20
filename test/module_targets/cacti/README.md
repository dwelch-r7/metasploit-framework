# Cacti module targets

These fixtures exercise `exploit/linux/http/cacti_unauthenticated_cmd_injection`
against genuine Cacti applications. Run them from the Framework repository root
with its Ruby and bundle, Docker Compose, Python 3 and NASM installed.

Verified on 2026-11-20: four owner profiles pass **24/0**, with nine owner sessions
and six independent handler sessions used and closed. The PHP native readiness
control fails and withholds its two owner cases. Older native-only controls add
no owner qualification. See [the verification record](../VERIFICATION-20261120-cacti.md).

The short session check uses the module's actual default target and payload,
then repeats on the same console selection with only `LOCAL_DATA_ID` supplied:

```sh
MODULE_TARGET_NAMESPACE=cacti-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb cacti_1222_default
```

Choose a namespace unique to your task. The guarded runner labels resources,
holds the shared test lock, runs stacks serially and removes their containers,
ephemeral networks and volumes on success, failure or interruption. Each Cacti
stack uses two capped application/database containers; session checks add one
capped reporting database. The Framework console runs on the host.

## Profiles

Case counts describe the suites. A dry-run or a native control alone does not
qualify an owner; the PHP profile remains an investigation.

| Profile | Cases | Purpose |
| --- | ---: | --- |
| `cacti_1222_default` | 3 | Native x86 staged handler, actual default echo stager, repeated owner session |
| `cacti_1222` | 6 | Refused-port check; manual, automatic and partially supplied IDs; exact quoting/Unicode/CRLF bytes with AutoCheck disabled |
| `cacti_1222_sessions` | 12 | Five native handlers and seven owner sessions: both architectures, echo/printf/wget/curl, Bash and repeats |
| `cacti_1223` | 3 | Native fixed-release controls, reason-bearing Safe check and both target bodies withheld by AutoCheck |
| `cacti_1222_php` | 3 | Investigate stock PHP Meterpreter readiness before the first/repeated PHP owner paths |
| `cacti_1216` | 1 | Native trust-boundary contrast; local command execution does not establish public forwarded-header access |
| `cacti_1217` | 1 | Native source/polling and local/public command controls, first execution and repeat |

Run a selected matrix with the same launcher, for example:

```sh
MODULE_TARGET_NAMESPACE=cacti-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb cacti_1222 cacti_1222_sessions cacti_1223
```

The older-release profiles are independent target controls. They do not invoke
the Framework owner and must not be counted as module qualification.

## Target identity and setup

The stock 1.2.22 application is the digest-pinned Vulhub image in `services.yaml`,
running Debian 11 and PHP 7.4.33 as `www-data` UID 33. MySQL 5.7.44 is also pinned
by digest. The database has no published port; the application is published only
on loopback. Default fixture database credentials are confined to the isolated
lab network.

`bootstrap.sh` uses Cacti's installation CLI with its EULA accepted and automation
disabled. Native controls discover the **Device - Uptime** graph template by name
and create its action-2 poller item with Cacti's graph CLI. They verify critical
source hashes, installed version, legitimate polling, unrelated-ID responses,
the non-poller denial and exact command-created file bytes before owner tests.
Version banners alone do not establish an exploitable fixture.

The 1.2.16, 1.2.17 and 1.2.23 images replace the complete application tree with
the immutable upstream revisions and archive checksums in `releases.json`.
Only the lab database configuration is retained. The 1.2.23 installer additionally
requires `intl` and `pcntl`; its recipe installs these using a dated Debian
snapshot and records installed package versions. Vulnerability checks and
authentication code are not patched.

## What the session checks prove

The independent handlers use real Framework payloads and transport before the
dependent Cacti paths run. Small source-built x86/x64 ELF controls must download
and actually exit with status 42. Successful sessions must execute through the
public session API as UID 33, produce the expected proof file, have real persisted
session records and close their process, transport and listener. Generated stager
ELF bytes and command lists are observed passively; downloaded inline executables
are bound to the running process by SHA-256. Stager files must disappear.

Default selection is checked before any explicit Cacti selection because
msfconsole restores cached options when the same module is selected again.

## PHP investigation

The original stock PHP handler control repeatedly received its stage without
becoming a usable session. A separate diagnostic reached bootstrap readiness
through a timing-changing TCP proxy, then stopped at a diagnostic metadata error
before session proof. The original direct-run cause remains unclassified.

`cacti_1222_php` performs a fresh stock control. Dependent owner cases are withheld
when readiness or cleanup fails; they are not reported as passing Cacti tests.
It uses the installed payload dependency without the private research patch.
The stock application also lacks `nc`/`ncat`, so Netcat is outside this fixture's
qualified paths.

## Evidence

Each run writes exact inputs, target identity, native commands, observed owner
calls, RSpec results, reporting queries and cleanup evidence under
`tmp/module-target-tests/<run>/`. A pending/filtered suite, a handler-only success
or an unclassified prerequisite failure is not a successful owner replay.

Upstream references:

- [Cacti advisory](https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf)
- [Pinned Vulhub setup](https://github.com/vulhub/vulhub/tree/9b90d4276f84feed6333286afeb7e1250379a1da/cacti/CVE-2022-46169)
- [Pinned Cacti 1.2.22 source](https://github.com/Cacti/cacti/tree/a0a8b7d51dcbe1ac0f91788e3579ac8962ba66ad)
