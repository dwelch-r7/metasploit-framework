# WordPress core SQLi qualification, 2026-11-17

This checkpoint adds **one runtime owner, nine qualified profiles and 22 functional
cases**, reaching **272 runtime owners in covered paths, 496 qualified profiles
and 3,700 historical functional cases**. Ten profiles and 24 cases were attempted;
the aggregate command correctly exits **1**. The subdirectory profile has one
incorrect recovered hash byte and contributes no accepted coverage. The broader
campaign remains incomplete. No PR is created.

The [reusable Compose labs](wp2shell/README.md) and public functional spec live
beside the other opt-in targets in this repository. Registration is separate from
qualification. Run the common preparation command, then select one or more
profiles with the guarded runner; it executes them serially. The existing human
module guides and Scenarios remain unchanged.

## Genuine application and independent controls

Unmodified official WordPress archives and every installed vendor file are pinned:

| Release | Installed files | Archive SHA256 |
| --- | ---: | --- |
| [6.9.4](https://wordpress.org/wordpress-6.9.4.tar.gz) | 3349 | `db610ad9f549e0abb5af3e3d5c6729c58d874439654cdf0afea425b2ea895f35` |
| [6.9.5](https://wordpress.org/wordpress-6.9.5.tar.gz) | 3349 | `d3587b549a6f5d90c6e4f4268ffc6c23671463625cf889a2c815a707ce9f5c41` |
| [7.0.1](https://wordpress.org/wordpress-7.0.1.tar.gz) | 3951 | `dc10592da9b580c7525632850e0cced371b13081853ac29afe93b5d5bb00db98` |
| [7.0.2](https://wordpress.org/wordpress-7.0.2.tar.gz) | 3945 | `d4a4d219dea64c6c68e62f2ffc3f331c5475510246d6c44f61fb52f377d295b9` |

The [official release advisory](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/)
and the affected/fixed source changes inform the branch selection. These four
releases are actually exercised; other branches are not inferred to be tested.
The pinned PHP 8.3.28 / Apache base receives core only in a fresh anonymous web
volume. Its upstream entrypoint creates the ordinary configuration. The native
installer creates real accounts and a post, with an ordinary MariaDB 11.2.2
application role. No plugins, cache drop-in or external object cache are enabled.
The host console has an isolated configuration and reports to an ordinary,
fresh PostgreSQL 16 schema. Owned lab configuration blocks mail and external HTTP.

Independent real HTTP controls exercise normal login/homepage/posts routes,
malformed batch dispatch, data-dependent boolean and timing predicates, and full
native in-band UNION recovery. Both affected releases return the complete native
login and 63-byte hash; both fixed releases reject the chain. Source, users,
metadata, posts and configuration are compared before and after public calls.
Native controls are repeated after execution, including on the failed profile.

An independent empty-post experiment shows that a direct per-post sleep becomes
flat when no posts exist, while the derived-table sleep used by the module still
executes. Full in-band recovery also succeeds. The empty-post public profile
therefore requires a complete successful extraction rather than an assumed
refusal. Native API operations create the custom prefix, plain permalink,
single-user and no-post variants; vendor source is never patched.

## Confirmed randomized alias defect

The original owner chooses a four-letter alphabetic SQL alias. Genuine native
requests using `join`, `like`, `desc` and `left` produce eight SQL syntax errors
and lose the expected rows/delay. Backtick-quoting the same aliases restores the
native rows and timing. The [MariaDB identifier rules](https://mariadb.com/docs/server/reference/sql-structure/sql-language-structure/identifier-names)
explain the reserved-word conflict. Independent native probes use scalar 313,
a DELETE source route and an `http://:` primer; these are not presented as exact
module-generated requests.

The narrow owner repair quotes its existing alias. Its random scalar range,
GET source route, `///` primer, nested requests, reporting and options are
preserved. Candidate `9555011e9b0daf090c3f5d6315833d9dbf454f18` is imported as
`05b64537108cee27145759764bb287c7ac9d9e31`. Fifteen owner unit cases plus seven
autoloaded support cases pass; the identical final unit input has ten failures
on the original owner and zero on the repair. Captured native error spans are
byte-checked. Unit RNG/HTTP doubles are explicit and separate from genuine SQL.

A preliminary original public root run passed all six cases. It is not claimed
as a failing functional reproduction of the alias defect and is not counted
again. Initial launcher and external-cache-flag assertions also failed before
module calls: an explicit Apache command and acceptance of the native falsey
cache flag correct those harness prerequisites. Their failed evidence is retained.

## Accepted public matrix

All rows below use aggregate run `20261117T013545-57c0cc`. Each has zero failures,
pending examples and outside errors, and successful teardown:

| Profile | Cases | Verified behavior |
| --- | ---: | --- |
| [wp2shell](wp2shell/README.md) | 6 | Public check; two complete runs with stable IDs; negative COUNT; closed-port check and run |
| [wp2shell_fixed69](wp2shell_fixed69/README.md) | 2 | 6.9.5 check and run refuse the chain |
| [wp2shell_70](wp2shell_70/README.md) | 2 | 7.0.1 check and complete extraction |
| [wp2shell_fixed70](wp2shell_fixed70/README.md) | 2 | 7.0.2 check and run refuse the chain |
| [wp2shell_prefix](wp2shell_prefix/README.md) | 2 | Native `wp_native_` tables and complete extraction |
| [wp2shell_plain](wp2shell_plain/README.md) | 2 | Native plain permalinks and complete extraction |
| [wp2shell_count2](wp2shell_count2/README.md) | 2 | Two complete distinct native credentials |
| [wp2shell_count_all](wp2shell_count_all/README.md) | 2 | COUNT=0 all-user branch on an actual single-user installation |
| [wp2shell_empty_posts](wp2shell_empty_posts/README.md) | 2 | No published posts; complete extraction still succeeds |

The accepted set includes ten checks and twelve runs: eight positive extraction
calls and four refusal runs. Eight deduplicated native credentials persist
across seven positive profiles, with complete 63-byte hashes, the correct
WordPress service, endpoint, private type and module origin. Repetition preserves
IDs. Eight exact loot files contain nine full records. Check and extraction
workspaces separately retain seven findings each. Jobs and sessions finish empty.
No HTTP, SQL, target-protocol or reporting doubles are used in functional cases.
The accepted profiles make 198 native gate requests, which are not extra cases.

## Unresolved subdirectory corruption

[wp2shell_subdirectory](wp2shell_subdirectory/README.md) has two attempted cases.
Its public check passes. Its public run returns normally but persists and writes
a hash whose zero-based byte 54 is `_` (95), while native truth is `e` (101).
Both values are 63 bytes; checking length alone would have missed the failure.
This profile contributes **zero qualified profiles and zero accepted cases**.

Before and after native controls, complete data/source/configuration equality,
resource limits and cleanup all pass. The target log has zero SQL error lines.
Its expected malformed-batch PHP warnings are not relabelled as SQL failures.
The failed assertion occurs before successful-loot bookkeeping; the actual loot
file is independently read and hashed rather than inventing a successful record.

The failed bisection comparison is `>95`. Server completion timestamps suggest a
roughly 0.632-second request even though the host classifier chose false, but
exact host per-predicate clocks were not captured. Shared `blind_request` uses
`Time.now`, which motivates an independent clock-robustness investigation; it
**does not establish the cause of this corruption**. A later passive host-clock
observer records 6,000 samples and no jumps, begins after the failure and cannot
settle that earlier cause. It exits naturally and its PID is confirmed absent.
No retry is used to erase this failure. The Docker restart announcement comes
after this failure; it is not used as its explanation.

## Verification, provenance and limits

All five changed/new test Ruby files have zero RuboCop offenses. Parent owner
unit execution passes 22 examples, zero failures. Full owner msftidy exits 2
with the same four pre-existing `Lint/RedundantPeerInPrint` warnings; direct
metadata checks pass. Both shell syntax checks pass. The optional source-preparer
archive extension preserves the ZIP default; four actual core tarballs and the
existing Secure Copy ZIP preparation pass. Three invalid extensions are rejected
before filesystem/Docker work. No dependency is installed.

Static inventory reports 5,179 source files, 273 registered owners, 500 manifest profiles, 29 individual reviews and zero stale reviews. These registration totals are not the qualified totals above.

All 97 consumed paths match fixture/source commit `42edf2b109051c6bbf8259c082222e7899cccaa0`:
93 exact tracked blobs and four ignored official tarballs. Actual runtime Git
revisions and input hashes are retained. The entire SQLi human guide remains
SHA256 `68c88207d535338932ac28659b4e4b5cba17dd0dd95d627bb5c19c7911861c44`;
the RCE guide remains `e478925bd9ac1137f4ed4ef3a19caae998a4e99504895bfa6b26005b4d517bb0`.

Complete blind extraction takes several minutes. Positive cases usually request
one account with SqliDelay=0.6; COUNT=2 separately covers multiple rows. COUNT=0
uses one real account to keep that limit branch short and does not qualify
multi-user unlimited extraction. Other runtimes, database versions, HTTPS,
external integrations and multi-target Scanner fanout remain unqualified.
Complete modern `$wp$2y$` hashes retain null `jtr_format` through the existing
shared classifier; format selection remains a separate follow-up. The separate
RCE module, its cache/administrator chain, both session families and cleanup
are not qualified by these SQLi results.

One stack runs at a time with at most three containers: app 1 CPU / 512 MiB,
MariaDB 0.5 CPU / 512 MiB and PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory,
PIDs are capped at 128, init is enabled and published ports bind loopback.
Both work/global observed maxima are three; no unrelated containers appear in
this batch. All 120 OOM/PID snapshots across the ten attempted profiles have
zero events. All 50 attached volumes/networks are independently confirmed absent,
all projects/global containers are empty and the aggregate finishes naturally
with exit 1. No unrelated image or volume is pruned.

The nine accepted runtime seals contain 1,089 independently rehashed entries;
the failed profile adds 121 preserved entries. Each seal retains the real
aggregate exit 1 and explicitly has no separate per-profile CLI exit.
The **52-entry** qualified checkpoint seal references **22 exact seals / 1,863 independently rehashed entries**:
`/Users/dwelch/.codex/reports/wordpress-core-sqli-qualified-checkpoint-20261117`,
manifest SHA256 `ad1038cd116e3b36a96b81c340dce76b77957762431feca3c663a4c5a92edcf4`. It preserves native prerequisites, initial harness mistakes, the original passing run, alias counterfactuals, worker proof, final mixed outcomes and earlier publication CI.
The [publication follow-up](VERIFICATION-20261117-publication-followup.md) records
terminal prior CI, including its actual upstream acceptance checkout. No extra
functional coverage is added for unit tests, native gates, prior attempts or CI.
