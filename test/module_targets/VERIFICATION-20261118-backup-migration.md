# Backup Migration execution, 2026-11-18

Qualified three profiles for `exploit/multi/http/wp_backup_migration_php_filter`,
adding **one owner and 21 cases**: **292 runtime owners in covered paths, 590
qualified profiles and 4,111 historical functional cases**. Final aggregate
`20261118T080015-17bca5` passes **21/0**, CLI exit 0, zero pending/outside errors
and successful teardown. Staged PHP is explicitly unqualified. The broader
campaign remains active; no PR is created.

## Reproduction and native prerequisites

Use the [shared target guide](backup_migration/README.md), linked from the
existing module documentation:

```sh
bundle exec ruby test/module_targets/backup_migration/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb backup_migration backup_migration_prefix backup_migration_fixed
```

The official Backup Migration 1.3.7 and 1.3.8 ZIPs and all 315 installed vendor
files per release are checksum verified. WordPress 6.8.3 / PHP 8.3.28 / Apache
and MariaDB 11.2.2 reuse the existing pinned WordPress Dockerfiles. Installation
and activation use UID 33. No vendor source or target HTTP handler is replaced.
The archives remain in the ignored cache; pinned sources and file manifests,
seed, Compose definitions, native controls and tests live together in the repo.

An owner-independent smoke run, `native-20261118t073316`, proves three exact-byte
UID-33 canaries on 1.3.7 and their absence on 1.3.8, including valid complete
path headers. Real WordPress login, wrong-password refusal, activation and vendor
integrity pass before/after. Its filter generator uses the literal table from
the [pinned primary PoC](https://github.com/Chocapikk/CVE-2023-6553/tree/30f0eff73edc04f93fbcbd143705b8dcde1687f7),
without loading the owner or Framework helper. Final controls use its captured
6,839-byte filter chain for the readable stub recorded alongside the fixture.
Apache header limits are unchanged. The vulnerable vendor endpoint sends an
incorrect Content-Length: native proof requires actual bytes and UID, including
when HTTP reading ends with IncompleteRead. HTTP 200 alone is insufficient.

Each fresh project has two containers, one stack at a time. Both are capped at
512 MiB, equal memory/swap, PID128 and init; app CPU is 1 and DB CPU 0.5. Only
the app exposes a random loopback HTTP port; its extra network permits the
independently verified UID-33 host callback. Framework runs on the host using the
existing Ruby 3.3.13 environment. Runtime inspections confirm these limits and
Linux/amd64. Compose adds project labels to built image configurations, so actual
image IDs differ per project; filesystem layers and all runtime configuration
apart from those labels match the independently built native images.

## Final functional results

| Profile | Plugin / base path | Cases | Genuine sessions | RSpec seconds |
| --- | --- | ---: | ---: | ---: |
| `backup_migration` | 1.3.7 / | 9/0 | 6 | 106.8 |
| `backup_migration_prefix` | 1.3.7 /wordpress | 9/0 | 6 | 81.5 |
| `backup_migration_fixed` | 1.3.8 / | 3/0 | 0 | 22.1 |

Each vulnerable profile covers the actual check, a handler-free command canary,
PHP stageless Meterpreter, Bash and Linux x64 HTTP/CURL-fetch Meterpreter, all
three session-family repeats, and an actual missing WordPress base path. The
second execution reuses the console configuration with AutoCheck disabled;
the first uses real AutoCheck. Framework creates separate execution instances.
The fixed profile checks Safe, proves normal AutoCheck refuses before the owning
exploit method, and checks the missing base path. Passive source-scoped traces
record **15 owner checks and 14 exploit entries**, including twelve sessions and
two sessionless commands. Nothing is inferred from session-open text alone.

Every session performs real file operations with exact independent bytes/UID33
and live PID UID proof. Meterpreter channel sets match before/after the file API.
Remote shell/Mettle child PIDs are absent before local registrations are cleared;
all four fetch files disappear through payload cleanup. Proof files are removed
and absence checked. PHP Meterpreter can occupy an Apache worker, whose PID is
never forcibly signalled or required to disappear. Each console finishes with
zero sessions/jobs and native WordPress/vendor controls pass afterward.

Six native before/after groups make twelve filter requests: eight exact UID-33
markers are created/recovered on vulnerable profiles and four remain absent on
the patched one. All **72 event-file captures (36 container/phase pairs)** show
zero OOM/PID-limit events. All **18 individual containers, volumes and networks**
are independently confirmed removed. Both Docker contexts finish empty. This
does not claim whole-filesystem, log, database or process-table equivalence.

## Preserved failures and limits

The first native harness omitted an unselected relative Compose dependency; its
successor assumed successful login lands directly on the profile page, while
the plugin first redirects to setup. Both failures precede owner qualification.

Original owner cohort `20261118T073922-b66329` finishes **10/2** solely because
idle shell registrations outlive their remote process. All seven actual session
proofs, including one staged PHP session, work. Cleanup-only replay
`20261118T074421-1d42e1` changes one of 69 inputs, with the owner unchanged, and
passes the six other session cases, including native child exit. Staged PHP then
enters a rapid invalid-session reconnect burst. Only that console process is
deliberately terminated; a later case/after-hook is affected by the interruption.
The replay is not a passing aggregate. Target OOM/PID counters stay zero.

The first three-profile aggregate, `20261118T075352-a925d1`, finishes **21/1**:
root 9/1, prefix 9/0 and fixed 3/0. Its one fetch-file assertion runs before the
adapter's intentional 3-7 second deletion delay completes. The final aggregate
changes **only that helper among the same 75-input union**, waiting up to fifteen
seconds for actual absence without harness deletion, and passes 21/0. All final
69/71/71 per-profile inputs match the captured bytes. Owner source SHA256 remains
`e5f6da2051fa8f286822df8c6b1b03eeb165ee08acc5b2d254e60f56c0e90fd6`;
no owner repair is claimed.

The [staged diagnostic](backup_migration_staged/README.md) remains outside
qualified totals. Its new separate definition is syntax/Compose checked, not
rerun; its RSpec phase is capped at 120 seconds, separate from setup/teardown.
Static review finds invalid sessions during TLV-encryption negotiation, before
Framework-side stdapi loading. Similar earlier WordPress-upload bursts do not
prove an identical initiating cause. Short-read and reconnect candidates require
bounded labeled transport evidence. No Backup Migration owner defect or shared
session repair is established; the [deferred record](DEFERRED.md) retains this.
Windows, other plugin/PHP/core releases, architectures, TLS/proxies, blocked
metadata and transport-loss behavior remain unqualified.

New Ruby passes syntax and scoped RuboCop; Python passes AST syntax and module
docs pass tidy. Human Scenarios are unchanged: 2,997 bytes, SHA256
`c694fc6cd8fb98eaf10cf61d60f5d20bd14af390bdb2d8ee9efe1b53518036b4`.
The existing owner is unchanged. SMB test/report logs independently verify the
prior published fork revision `4ac43b127796f270471981396a969454dca43b8d`, with
20/0. Its [Linux Mettle job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44256851609/job/134640482997)
finishes 51/1 after recursive directory removal reports Send timed out over
reverse HTTP with `minimal_uris_headers.profile`; macOS passes 46/0. Both jobs
and the final report prove that exact checkout. The cause remains unverified;
these CI jobs do not execute the new opt-in module profiles.

Read-only final evidence has 329 entries at
`/Users/dwelch/.codex/reports/backup-migration-qualified-20261118T080015-17bca5`,
manifest SHA256 `025c3828b2e3dd4ec7f92a3f2c0ca22b71cc7e30d52e4d0d2c30375b8f0b17a9`.
It references separately sealed native, original, interrupted replay and first
aggregate evidence. None of those prior runs is added to passing case totals.
