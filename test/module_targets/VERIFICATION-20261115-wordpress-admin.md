# WordPress administrator upload and PHP shell checkpoint

Four bounded profiles pass **23 distinct cases and 29 public module calls** on
WordPress 6.8.3 / PHP 8.3.28. They cover root and prefixed installations,
WordPress's real upload restriction, and unrelated Apache. Four plain PHP shells
and four stageless Meterpreter sessions were used to create fresh `www-data`
files and explicitly closed. Four finite PHP executions passed with explicit
operator cleanup. This is scoped qualification, not campaign completion.

The two staged Meterpreter profiles remain **unqualified**. Each used its first
session successfully, then entered an invalid-session reconnect burst during the
second execution. Both were interrupted deliberately with incomplete test counts.
The initiating cause remains unverified; these observations do not establish an
upload-module defect.

## Actual target and functional paths

Use the [component guide](wordpress_admin/README.md) and guarded runner. Each
WordPress project contains one actual installation, its database and Framework;
the unrelated project contains Apache and Framework. At most three containers
run, one profile at a time. CPU, memory and PID limits and `init` are configured
for every role. Only random loopback HTTP ports are published.

| Profile | Cases | Public calls | Retained actual run | Outcome |
| --- | ---: | ---: | --- | --- |
| `wordpress_admin` | 11 | 14 | `20261115T135450-8848e3` | Passed |
| `wordpress_admin_prefix` | 8 | 11 | `20261115T135810-0ab08c` | Passed |
| `wordpress_admin_locked` | 2 | 2 | `20261115T140100-777b0e` | Passed |
| `wordpress_admin_unrelated` | 2 | 2 | `20261115T140513-22918c` | Passed |
| `wordpress_admin_staged` | Incomplete | 2 | `20261115T140647-df1caf` | Controlled interruption |
| `wordpress_admin_prefix_staged` | Incomplete | 2 | `20261115T141123-93aff7` | Controlled interruption |

All normal passing reports have zero pending cases and outside errors. The
original 25 example bodies, assertions, repeat loops and cleanup helpers are
preserved across the six profiles. Collection checks established exact coverage
without duplicated, missing or silently skipped cases; they did not substitute
for these actual runs. Staged cases retain historical seed 7721.

Independent native controls inspect real versions, paths, accounts, roles,
capabilities, command execution and filesystem policy. Standard HTTP/RubyZip
clients upload, execute and remove a harmless plugin twice per enabled
installation. This independently proves four upload/execute/remove cycles across
root and prefix. The locked profile proves genuine policy denial despite valid
administrator authentication. Real PHP callbacks establish the internal listener
path; unrelated Apache is checked separately. These controls do not call the
owning module's authentication, upload or payload helpers.

Every owning success path repeats twice. Session cases require a fresh file with
the web account owner and artifact absence before failed-case recovery. Finite
PHP execution explicitly enables `AllowNoCleanup` and verifies operator cleanup;
it does not claim automatic cleanup without a session. Wrong passwords, missing
accounts, limited accounts, policy denial and unrelated HTTP exercise negative
paths. Other versions, platforms, TLS, remote filesystem methods and Framework
database credential persistence remain outside this checkpoint.

## Confirmed payload defect and isolated repair

The first root run, `20261115T131807-ccff90`, completed 11 cases with one failure.
Finite PHP execution and two usable stageless Meterpreter sessions passed. Its
plain PHP shell opened and immediately became unusable. Apache recorded PHP
8.3.28 raising `ValueError` when the generated command wrapper called
`shell_exec('')`. Resource counters did not show OOM or PID-limit events.

`CommandShell#shell_read_until_token` sends a bare command terminator after a
successful token read. `php/reverse_php` stripped that terminator and dispatched
an empty command. The repair returns an empty result for blank commands in the
common generated wrapper. It leaves nonblank command bytes, both transport
branches, callback options and the shared PHP generator unchanged.

An independent generated-code replay used real PHP 8.3.28 with both `fsockopen`
and the actual raw-socket fallback. A test-only image compiled sockets from its
exact bundled PHP source, without adding OS packages or changing production
recipes. The identical 38-case matrix changed **8 failures to zero**, with 30
baseline controls already passing. It covered execution-function selection,
newlines, whitespace, command `0`, ordinary and UTF-8 output, existing padded
output normalization, directory changes, exit/quit and EOF. Nonblank outputs
matched the original. All fixed-run PHP children exited and were reaped; OOM and
PID-limit counters remained zero.

Nine focused generation examples changed one expected failure to zero. Strict
RuboCop, msftidy, syntax and diff checks passed. Generation tests stub layout
randomization; they are distinct from the real interpreter/transport replay.
PHP 5.6 consumer replay is tracked separately through the bounded Drupal profiles.

| Protected or changed source | SHA-256 |
| --- | --- |
| Unchanged `wp_admin_shell_upload.rb` | `d1e640a23c27d6c2b983380b44bc4c8c493a003fefe35573994c9dad43474924` |
| Original `php/reverse_php.rb` | `380c135cefcd5d64fc3c0d429bd7af2729af08ee7f6f5952dc61be1d012c0d1c` |
| Repaired `php/reverse_php.rb` | `1a38a7d8eed0ca7275b24a866aac70540b4fd2409b42d1d04f05a3f8ab674aba` |
| Unchanged whole WordPress module guide | `c33d17b48895ad65b3776c65f34108ad8fe26cc9bcda836d63a4972978f920e9` |

The fix is worker commit `ba6fafc893b` / integrated commit `35ae10ea310`.
No upload-owner, shared PHP generator, payload timeout or human scenario changed.

## Fixture and staged-session findings

The first unrelated-Apache run, `20261115T140231-74b1f1`, stopped in the resource
before hook. Apache event MPM could not create its normal worker threads under a
64-PID cap (`AH03104`); `pids.events:max` was 30 before native or module calls.
The two failed examples and one outside error share that setup cause. Raising
only this profile's cap to 128 PIDs preserved the counter assertion, CPU and
memory limits; the actual two-case replay passed with zero PID-limit events.
The matching Drupal control cap was corrected before its actual replay.

For both staged profiles, native preflight passed, the first session created a
fresh `www-data` proof file, and the second public execution produced the reconnect
burst. Root was stopped after 836 observed invalid-session messages. The prefix
observer stopped after 24. Each original guarded runner reached a terminal
SIGINT result, and each archive retains null completed counts. These are two
interrupted investigations, not hundreds of failed tests. Both before/after
resource phases were retained with zero OOM and PID-limit violations.

The passing root stageless case also logged one additional Meterpreter session
closing with `Reason: Died` before an opened banner; a later session was used and
closed successfully. That extra connection is not counted among the eight usable
main-profile sessions. Its initiating cause is unverified. Passing repeated use
does not establish perfect bootstrap reliability.

Initial isolated-probe calibration errors are retained separately: expected
padded output differed from PHP `exec` normalization, sockets were initially
absent, and a command-`0` fixture could not execute from a noexec tmpfs. Exact
absence parsing and an image-declared anonymous volume also needed correction.
None of those draft failures establishes a production payload defect. The final
before/after matrix uses identical corrected control inputs.

## Evidence and cleanup

Local exports live under `/Users/dwelch/.codex/reports/`. Each functional export
contains the actual run, all 70 declared inputs, source hashes, real console and
native captures, exact owned resource identities and independent cleanup checks.
All eight completed WordPress run exports passed six parent Docker queries and a
released-lock check. Known container IDs, network IDs and volume names were
absent, and the global container inventory was empty between profiles.

| Export directory | Manifest SHA-256 |
| --- | --- |
| `wordpress-admin-php-shell-failure-20261115` | `6a9cd24db0e8361ad1cff51ad8bd645ab0045c165f3616baf2dcb05a4b2eeda6` |
| `wordpress-admin-root-qualified-20261115` | `4340cd3f03b92ecb9b8fbfdb1ca51ac06f33b2a9fdb67e852f682005722611ef` |
| `wordpress-admin-prefix-qualified-20261115` | `f42433e01f783e2488ce1cfd0fdaaab2bb28e675078837e830dc5a4f34696a94` |
| `wordpress-admin-locked-qualified-20261115` | `a63fcea05745da7cc66e5c5aef556e148fc6d8a6fc2fbfe646d2486545f4846d` |
| `wordpress-admin-unrelated-failure-20261115` | `c8663f6e0af84ecc96ead95bbbe8803172784309ad15edcf155483b143c9bd27` |
| `wordpress-admin-unrelated-qualified-20261115` | `8ee06fdbd15f0f7e4430d4134ca5f2e84e7efd1cb7b55bb38c2813553e1f0b08` |
| `wordpress-admin-staged-reconnect-20261115` | `0f7b10a296578c7befb1ee0d49398479d0af17885f180e6ba3309cfbd4df705a` |
| `wordpress-admin-prefix-staged-reconnect-20261115` | `b18919a6d28e0ed1edc552263b197b1ade5a8826f93a82227d213860b16a4a54` |
| `php-reverse-empty-command-repair-20261115` | `c6868e2812be32743ff4585669087e4d74890c87505e8e982447293b77a98565` |

The passing root export predates a README-only correction documenting Apache's
128-PID limit. Its module, payload, helpers, acceptance cases and root fixture
still match the tested inputs; the frozen documentation hash is retained rather
than rewritten. No functional replay is claimed for a documentation-only edit.
The interrupted root exporter initially expected a complete RSpec summary; its
retained export-tool error was corrected to preserve incomplete JSON and null
counts. This did not change runtime inputs or test outcomes.

The broader feasible-module campaign remains active. Cumulative qualification
updates must also account for the repaired payload's Drupal consumers; older
families retain their own frozen source and coverage limits.
