# Native PHP reverse-shell regression target

The reusable `php_reverse_php` component passes **38 native functional
contracts** against the repaired payload. The same component reproduces eight
failures against the frozen original source; its other 30 controls pass. This
adds one profile and 38 cases, with no additional exploit/scanner owner.

Run it through the [component guide](php_reverse_php/README.md). One capped
container executes the actual generated PHP through real loopback TCP, with
both `fsockopen` and the genuine sockets fallback. No console, handler, published
port, host bind mount or external network is needed. The existing WordPress and
Drupal profiles establish application and Framework session integration
separately.

## Before and after evidence

| Source | Actual run | Cases | Failures | Result |
| --- | --- | ---: | ---: | --- |
| Original override | `20261115T151218-c3153f` | 38 | 8 | Reproduces empty-command failure |
| Repaired source | `20261115T151253-9361fe` | 38 | 0 | Separate-worktree replay |
| Repaired primary checkout | `20261115T152545-b2c001` | 38 | 0 | Integrated replay, 16.6 RSpec seconds |

All three reports have zero pending examples and outside errors. The original
source SHA-256 is
`380c135cefcd5d64fc3c0d429bd7af2729af08ee7f6f5952dc61be1d012c0d1c`;
the repaired source is
`1a38a7d8eed0ca7275b24a866aac70540b4fd2409b42d1d04f05a3f8ab674aba`.
The original-source override is explicitly recorded and does not qualify the
current checkout. The production repair and its application consumers were
already established in the [WordPress checkpoint](VERIFICATION-20261115-wordpress-admin.md).

The eight original failures are newline probes reaching `passthru`, `shell_exec`,
`system` or `exec` over each transport on PHP 8.3.28. The repaired generated
wrapper returns an empty result before invoking a helper for a blank command.
It preserves nonblank command bytes, including the executable command `0`.
The shared generator and execution-helper order are unchanged.

Each conversation checks exact output and process completion. The matrix covers
all six execution helpers, newline/whitespace/empty probes, ordinary and Unicode
output, significant spacing, compound commands, command `0`, directory changes,
exit, quit and EOF. Every child is reaped and temporary generated files are
removed. Host generation uses the actual payload source and public `generate`
API, with dedicated metadata output rather than parsing incidental stdout.

## Resource and verification evidence

The target uses user 33, 0.5 CPU, 192 MiB, 64 PIDs, init, a read-only root,
bounded tmpfs directories, dropped capabilities and `network_mode: none`.
The inherited application volume is overridden by tmpfs; the primary run creates
no Docker volume. The digest-pinned PHP 8.3.28 base compiles only its bundled
sockets extension with one build job and adds no OS or project dependencies.
Resource counters are captured when readable; unavailable files are explicitly
reported, rather than interpreted as zero.

The primary guarded run exits normally. Six independent parent Docker queries
and a released-lock check confirm the exact container is gone and the global
container inventory is empty. Docker's built-in `none` network is retained.
The separate original/fixed runs also complete teardown and independent cleanup.

Three new Ruby files pass strict RuboCop and syntax checks. Collection selects
exactly 38 native cases. Default CI performs no native capture: the focused
combined invocation passes nine existing payload-generation examples and seven
autoloaded datastore-formatting support examples, while excluding the native,
WordPress and Drupal functional bridges. These 16 examples do not increase
functional totals. No full local RSpec suite was run.

Early fixture failures remain separate: a metadata key mismatch and coverage
footer on stdout caused a suite-level setup error, before the dedicated metadata
file correction. Earlier pre-centralization runs are retained. Neither these
setup failures nor the private precursor matrix add qualification counts.

The separate-worktree export `php-reverse-native-target-20261115` contains 228
file entries, all independently rehashed, including five run trees and 31 final
declared inputs. Manifest SHA-256:
`847650f83d9851d5ca204700110987c9d087a911bcd97197c3fd540344a355bf`.
The integrated export `php-reverse-native-primary-20261115` contains 65 entries
and 31 inputs. Manifest SHA-256:
`b70d0f492a8908310e5f1dec11daede6a0ef83a962626f036612a6e0cfbd2cb3`.
Both are local evidence exports under `/Users/dwelch/.codex/reports/`.

## Recorded campaign checkpoint

Recorded coverage advances to **249 runtime owners in covered paths, 340
profiles and 3,129 functional cases**. The payload component contributes one
profile and 38 cases, with zero new runtime owners. Older families retain their
own frozen inputs; no whole-campaign replay or completion is claimed. PHP 5.6,
IPv6 and the separate staged PHP Meterpreter reconnect failure are outside this
component's qualification. Human module Scenarios are unchanged.
