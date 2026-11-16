# WP Fastest Cache credential gathering, 2026-11-16

This checkpoint adds **one runtime owner, nine profiles and fifteen functional
cases**, reaching **266 runtime owners in covered paths, 450 profiles and 3,592
functional cases**. The [module source](../../modules/auxiliary/scanner/http/wp_fastest_cache_sqli.rb)
and [human module guide](../../documentation/modules/auxiliary/scanner/http/wp_fastest_cache_sqli.md)
map to the Compose profiles through their module manifest entries.
Earlier coverage remains historical. The broader campaign
is incomplete; registration is separate from runtime qualification. No PR is
created.

The final matrix has 15 real public `run` calls, 54
independent native HTTP requests, 5 exact loot files and
5 deduplicated credential rows across isolated profile
workspaces. Full hashes are compared with genuine Core user records. Negative
states save no credentials or loot. No HTTP, SQLi, persistence or loot transport
is stubbed in these functional cases. The module has no public check hook.

## Genuine targets and prerequisites

Unmodified official WP Fastest Cache **1.2.1 / 1.2.2** archives run on pinned
WordPress 6.8.3 / PHP 8.3.28 and MariaDB 11.2.2. Exact archive and installed
critical-file SHA256 values live in [the release catalog](wp_fastest_cache/releases.json).
The [original research](https://wpscan.com/blog/unauthenticated-sql-injection-vulnerability-addressed-in-wp-fastest-cache-1-2-2/)
and vendor patch identify 1.2.2 as fixed. This qualifies the pinned pair,
not every earlier release. The human guide's broader affected-boundary text
is left untouched; use the exact setup pair documented here.

Native Core APIs install four real users, activate the plugin and save its
settings. Merely activating the plugin does not reach the injection: the
cache-status property must exist. Its real logged-in-user exclusion returns
before the vulnerable query for a login cookie. Disabled caching omits the
status property, rather than assigning an invented off value. Inactive and
absent states retain genuine WordPress login behavior.

Three preliminary native probes independently qualify affected, patched and
logged-in-exclusion states: 42 HTTP requests, both OR and module-shaped AND
true/false cookie expressions, source/role checks and cleanup. Their 189 sealed
entries are independently rehashed. They add no module functional cases.

The final matrix independently verifies ordinary login, a different OR-cookie
SLEEP expression before/after each profile, actual source hashes, ordinary
MariaDB and Framework/PostgreSQL roles, four native users, plugin settings and
matching native identity/user/setting snapshots. This is not a complete
byte-for-byte database snapshot. A failed native gate is a setup/qualification
failure; it does not prove correct module rejection.

## Confirmed helper defect and correction

The original default-prefix probe searches all visible databases. A real
`wp_prefix.wp_users` backup causes it to select `wp_` even though the connected
site uses `wp_root.wp_native_users`. Native controls prove the injection works
and both genuine tables contain four users. The original public module returns
with empty loot and zero credential rows; the same public test fails.

The helper now scopes its default probe to `table_schema = database()` and
compares the raw complete indicator string. The latter also prevents an empty
or malformed result becoming zero when the random indicator is zero. The
String/nil return contract is preserved and documented. Ten consumers were
identified; no module-specific extraction transport is changed.

A separate worktree supplies commit `703f8c8025513608aa2d20447556f60c5ab700ec`,
imported as `f769425c7ce`. The same fifteen focused unit cases have six original
failures and zero corrected failures. All 134 existing Photo Gallery, Depicter
and BookingPress unit cases pass before and after. These tests model transport
and add no functional coverage. The worker's 45-entry seal is
`/Users/dwelch/.codex/reports/wordpress-sqli-prefix-scope-20261116T144943Z-seal`,
manifest SHA256 `20d69d513626a0ce76418bc5dba76df0c567eaf4f1fba159c63731a98edcff36`.

The exact original native custom-prefix test is then replayed: one failure
becomes one pass, with a complete real hash, credential and loot. The helper
is the only changed declared input. Original, corrected diagnostic and final
qualification records remain separate. The corrected diagnostic seal has
101 independently rehashed entries and manifest SHA256
`dad5d71adf9c43953ce98de4f996707966cd5d3a6fa7c0c6a1b6d3f57eeedc17`.

The unchanged owner SHA256 is
`dd1297a79c51d7b6fc8332e35e4ae8a367e726bdb6790799d4ddd1445688de81`.
The original/fixed helper SHA256 values are respectively
`4254db459fc385e34fcd71657023ddd71afe11034161c4044cf73265103e0777` and
`8bd9bd0e0b42b8f00bda61071053d72443f0942ab7b7745efb104ca2092856de`.
The entire human module guide and Scenarios remain byte-identical:
`edf82444c4e81903801e9eaef04c11af13a849cdb713333f831537b04e3d0298`.

## Final functional results

| Profile | Actual run | Cases | Public calls | Native HTTP | Exact loot |
| --- | --- | ---: | ---: | ---: | ---: |
| `wp_fastest_cache` | `20261116T152116-138a40` | 2 | 2 | 6 | 2 |
| `wp_fastest_cache_absent` | `20261116T145818-c53b82` | 2 | 2 | 6 | 0 |
| `wp_fastest_cache_count2` | `20261116T151409-b2c536` | 1 | 1 | 6 | 1 |
| `wp_fastest_cache_disabled` | `20261116T150145-43554b` | 2 | 2 | 6 | 0 |
| `wp_fastest_cache_excluded` | `20261116T150322-6585d2` | 2 | 2 | 6 | 0 |
| `wp_fastest_cache_fixed` | `20261116T145617-8f2a5c` | 2 | 2 | 6 | 0 |
| `wp_fastest_cache_inactive` | `20261116T150004-937299` | 2 | 2 | 6 | 0 |
| `wp_fastest_cache_prefix_otherdb` | `20261116T150459-c691c6` | 1 | 1 | 6 | 1 |
| `wp_fastest_cache_subdirectory` | `20261116T150951-7277ef` | 1 | 1 | 6 | 1 |

The default profile repeats COUNT=1; a separate profile retrieves two complete
rows with COUNT=2. Genuine subdirectory and cross-database prefix paths succeed.
All five fixed/missing-prerequisite states repeat the public run and save
nothing. Local SqliDelay=0.4 is calibrated by independent native controls; full
time-blind hash extraction still takes several minutes. This delay is not a
recommended setting for noisy remote networks.

Two existing Photo Gallery profiles additionally replay the helper's
union-based/default/custom-prefix path: 14 cases,
28 public calls, zero failures. They retain their existing
fixtures and add no new coverage counts. Their reporting fixture is unchanged;
this is helper-consumer regression evidence, not a new unprivileged reporting
qualification for Photo Gallery.

## Resources, reproducibility and limits

Every final stack has three capped containers: WordPress 1 CPU / 384 MiB,
MariaDB 0.5 CPU / 512 MiB, and ordinary-role reporting PostgreSQL 0.25 CPU /
384 MiB. Swap limits equal memory, PID limits are 128 and init is enabled.
Published ports bind only loopback. The reporting component reuses the existing
Elasticsearch PostgreSQL service definition without starting Elasticsearch.
All 108 before/after OOM/PID event rows are zero. Each stack
is removed before the next. Projects, attached volumes and networks are
independently verified absent; final Docker inventory is empty and the advisory
lock is free. Personal orchestration removes unrelated containers under the
user's explicit instruction; the committed guard itself refuses them.

The [lab README](wp_fastest_cache/README.md) supplies preparation and serial
Compose-backed runner commands. Source/fixtures are committed as `e984a5670a9333ad8888334d996133aeccd7da8c`.
All 85 tracked consumed inputs match that commit;
2 ignored archive caches match the catalog and
sealed exact bytes. Runtime records retain their actual earlier HEAD and
working-file hashes, rather than claiming an earlier checkout of a later
commit. The 910 final runtime archive entries are
independently rehashed with exact file sets.

Changed library/spec/fixture Ruby has zero strict RuboCop offenses; focused
before/after units, syntax, resolved resource/binding checks and diff checks
pass. Existing source metadata and human documentation are not broadly edited.
CI publication follow-up for the preceding checkpoints is recorded separately
in [the publication journal](VERIFICATION-20261116-publication-followup.md).
Other WordPress/PHP/database releases, SQL modes, aggregation limits, TLS/IPv6,
COUNT=0/all-row extraction and noisy network timing remain unqualified.

The static queue has 5,179 source files, 4,622
module candidates, 267 registered owners and 4,332
pending reviews, including 238 container hints.
Its 26 individual reviews have 0 stale source hashes.
Registration continues to exceed runtime owners by the recorded historical
one-owner difference.
