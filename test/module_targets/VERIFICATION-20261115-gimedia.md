# GI-Media Library file disclosure qualification

All five genuine profiles pass **20 functional cases and 42 public module calls**,
including eighteen exact file loots. A separate check-hook fix makes the existing
version check available through the public scanner API. The download method is
byte-identical. This adds one runtime owner and five profiles.

## Targets and measured results

The [component guide](gimedia/README.md) provides archive preparation and serial
guarded commands. It reuses the existing pinned WordPress 5.2.4 / PHP 7.3.11 image,
bootstrap, database and shared archive helper. Official GI-Media Library 2.2.2 and
3.0 ZIPs are checksum-pinned in [the release catalog](gimedia/releases.json).
WordPress APIs install and activate unmodified vendor code. No endpoint, version
response or file read is simulated. The unrelated control is genuine Apache.

| Profile | Cases | Public calls | RSpec seconds | Actual run |
| --- | ---: | ---: | ---: | --- |
| `gimedia` | 7 | 15 | 39.9 | `20261115T185715-e68a82` |
| `gimedia_prefix` | 7 | 15 | 41.0 | `20261115T185829-0eceb5` |
| `gimedia_fixed` | 2 | 4 | 43.2 | `20261115T190007-ba968f` |
| `gimedia_absent` | 2 | 4 | 41.2 | `20261115T190129-07c676` |
| `gimedia_unrelated` | 2 | 4 | 40.5 | `20261115T190243-37bfee` |

Every final invocation exits zero with no failures, pending cases or outside
errors. Timings include native controls and cold host-console startup; target
build/setup time is separate. Each invocation uses isolated console configuration
and metadata caches.

Native inspection runs as the web user and verifies core/PHP/plugin identity,
active plugins, archive/endpoint hashes, file readability and actual bytes.
**32 independent HTTP requests** establish affected disclosure, genuine fixed
refusal, plugin absence and the unrelated marker before owner commands. The 3.0
archive removes `download.php`; its real 404 is verified alongside a working
WordPress installation and active 3.0 plugin.

Affected profiles repeat real system-file and binary-file reads. UTF-8, NUL and
0xff bytes must survive exactly. Unicode/space/apostrophe filenames, relative
paths and the default `wp-config.php`/depth 3 values are exercised. Root traversal
uses depth 6; the `/wordpress` installation uses 7. Each download creates exactly
one fresh loot file with the actual length and SHA-256. Missing/empty files,
insufficient depth and missing installations must create no loot or success
claim. The vendor endpoint cannot distinguish empty content from a failed read;
empty files are negative controls. Quoted paths are genuine positive controls
here, separately from the recorded DukaPress limitation.

Checks run twice and must actually be supported: Appears for 2.2.2, Safe for 3.0
and Unknown for absent/unrelated targets. A message saying check is unsupported
cannot pass a negative case. Negative runs also repeat. All fixture file bytes,
active-plugin state and administrator password/activation-key fingerprints remain
unchanged; the identity comparison is not a full database audit. Sessions and
jobs remain empty. Ordinary service audit logs persist until teardown.

## Original failure and repair

Original run `20261115T185206-1592f7`, exec 7119, exits one: **seven examples, one
failure, fourteen completed public commands**. Native preflight passes all ten
HTTP controls and all six download cases pass, including nine exact loots. The
sole failure is the public check reporting `This module does not support check.`
The original result is sealed before any source or fixture edits.

`MultipleTargetHosts#has_check?` requires the scanner `check_host` hook. This
owner instead overrides `check`, so console capability discovery rejects its
otherwise working version helper. Separate-worktree commit `d371219d0ca`
integrates as `e6bb81f5f3d`: it exposes `check_host(_ip)` and follows mixin order.
The inherited public check API remains. `run_host` through EOF stays byte-identical,
SHA-256 `9fd4dd815ef4dc1bccd010b1aa93b928f46ecd8ba0a0ffe3a532f80abcaea87c`.

Original owner SHA-256:
`1b375ae0b43318a4343628fa13263cff0735cd330d1da1f234e885eaea7a5fda`.
Repaired owner SHA-256:
`6a1938a2897636204b1542ab093ba3f8fe60f9667fd332620b0d50d9b28b3700`.
The identical final unit suite/seed 7721 reports nine examples/eight failures on
original source, then nine/zero on the repair, with no outside errors. Direct
original Ruby checking is a passing control. HTTP, lifecycle, reporting/events
and listener boundaries are doubles; actual public `check_simple`, capability
discovery, validation, replicants, WordPress version extraction and Rex comparisons
execute. The affected document reduces the actual readme to its name and Stable
tag lines, retaining CRLF. Fixed/missing/unversioned inputs are labeled synthetic.
Unit failures are not counted as separate native defects or functional cases.

Strict owner lint retains six existing offenses, down from seven because the
old missing-AutoCheck complaint disappears. Zero new offenses or suppressions
are introduced. Module tidy, syntax and diff checks pass. Five fixture/new-spec
Ruby files have zero strict-lint offenses. The focused primary default selection
passes **84 executions / 77 distinct examples**: nine GI-Media, nine DukaPress,
37 POST SMTP, fifteen WordPress-user and seven formatting examples. The seven
formatting examples load automatically and were also selected explicitly. The
private post-check's incorrect expected execution count returns one after all
four commands pass; this counting error and raw output are retained separately.
No behavior/test failure is hidden or retried. The new functional bridge is
excluded from this default selection. No full local suite is run. No existing
module guide or human Scenarios were changed, and none were invented.

## Resources, cleanup and evidence

Only one capped stack runs at a time. WordPress uses 0.5 CPU / 384 MiB / 128 PIDs;
MariaDB uses 0.5 CPU / 512 MiB / 128 PIDs. Unrelated Apache uses one container at
0.25 CPU / 128 MiB / 128 PIDs. All use init. Actual inspection matches those
limits; every role has zero before/after OOM/PID-limit counts and no OOMKilled
flag. HTTP binds a random loopback port; the database is internal-only. The host
Framework console runs under `nice` outside target memory/process cgroups.

**Thirty independent cleanup queries and five released locks** establish all
nine exact container identities, nine networks and eight volumes absent. Docker
is empty between profiles and after the final run. All five final recorded input
maps match current selected source, helpers and cached archive bytes. Their
read-only exports retain **511 independently rehashed entries** under
`/Users/dwelch/.codex/reports/`, including native CLI/HTTP, raw console, exact loot,
resource/cleanup records and frozen inputs.

| Export directory | Manifest SHA-256 |
| --- | --- |
| `gimedia-20261115T185715-e68a82-sealed` | `096d2ef1f38f7f16beea1e974022610d1a83a170e23e3a6d2ac449e7c07ad363` |
| `gimedia_prefix-20261115T185829-0eceb5-sealed` | `276cb8b3d3c6ebc79952ca70fe7ff14c01ac1426d728f3d3e3cff9a0e31fed46` |
| `gimedia_fixed-20261115T190007-ba968f-sealed` | `979624f251d5bfc06d4f5e690b2d4dead9f2538772cf0f8e207a07b838b180b9` |
| `gimedia_absent-20261115T190129-07c676-sealed` | `ae321fec8419420824c109f39725f6778ab776d1bfe0676b5a9b533c73bf8f6b` |
| `gimedia_unrelated-20261115T190243-37bfee-sealed` | `154c47255519a7600c55bbdf5c4acd9ffaeb34133d65cd83c1d577aa8e31ba91` |

The original failure export `gimedia-20261115T185206-1592f7-sealed` has 106 rehashed
entries, manifest `60b0e3f8510543fa83a44d2e667f2eb8ce365ba8186cfbbce671b09e2b67b9da`.
The source-repair export `gimedia-scanner-check-repair-20261115` has 75 rehashed
entries; its `MANIFEST.sha256` hash is
`66d61165ea19a14a6e942c9a8627ac07a2e73d977b7a7d3f500f1bbe6a25c2ad`.
The controller retains actual original exits separately from test summaries.

## Recorded campaign checkpoint and limits

Recorded coverage reaches **253 runtime owners in covered paths, 363 profiles
and 3,195 functional cases**. This adds one owner, five profiles and twenty cases
to [the DukaPress checkpoint](VERIFICATION-20261115-dukapress.md). Earlier families
retain frozen qualification inputs; no whole-campaign replay is claimed.
The static inventory now records 5,179 sources, 4,622 selectable candidates,
254 registered owners, 4,345 pending candidates, 248 pending container hints and
26 reviews with zero stale reviews. Registration is not passing qualification.

Only the selected 2.2.2/3.0 plugin and WordPress/PHP/runtime profiles are qualified.
Other releases, PHP/core combinations, alternative content directories, HTTPS
and other deployment layouts remain unqualified. Synthetic unit boundaries do
not establish those targets. The six existing lint offenses remain disclosed.
The staged PHP reconnect investigation and broader feasible-module campaign
remain open. No PR is created.
