# Ultimate Member SQLi qualification, 2026-11-17

This checkpoint adds **one runtime owner, eleven profiles and fifteen functional
cases**, reaching **271 runtime owners in covered paths, 487 profiles and 3,678
historical functional cases**. The [reusable profiles](ultimate_member/README.md)
exercise the existing sorting SQLi module through real public `run` calls. The
owner has no public check implementation. Earlier coverage remains historical;
the broader campaign remains incomplete. No PR is created.

## Genuine source and native prerequisites

Unmodified official archives and every installed plugin file are pinned:

| Release | Installed files | Archive SHA256 |
| --- | ---: | --- |
| [2.8.2](https://downloads.wordpress.org/plugin/ultimate-member.2.8.2.zip) | 659 | `447fb24e2fa8e6df2bb02da18acd66977ef1070c4c8ae5ae4f4a77e1f92fe3ba` |
| [2.8.3](https://downloads.wordpress.org/plugin/ultimate-member.2.8.3.zip) | 661 | `f46d84135a292a645afd3a18548382cd7e9d7414064cdf3ec95cf0333bf516b2` |

Pinned WordPress 6.8.3 / PHP 8.3.28 and MariaDB 11.2.2 run with an ordinary
application database role. The isolated host console reports to a fresh,
non-superuser PostgreSQL 16 schema. Native activation installs forms, a directory
and four ordinary WordPress accounts' member status. The native setup API creates
its pages. The vendor's actual nonce-checked admin migration operations enable
and populate the custom metadata table in separate PHP processes. Migrated rows
must exactly match native core metadata; vendor source is unchanged.

Two initial native probes fail because the default empty role selector returns
zero members before issuing its custom-table SELECT. Selecting all native roles
through WordPress's post-metadata API produces all four genuine members. The
empty selector remains a separate negative profile. It is a prerequisite result,
not evidence that the module or the SQL transport is broken.

Independent data-dependent timing probes succeed on 2.8.2 and remain flat on 2.8.3.
Both raw and module-shaped controls are qualified before module testing. Actual
installer page 11 redirects to `/register/`, which contains a genuine nonce;
a nonexistent page can return 404 with the global nonce too. Default scanning
therefore does not universally fail on the original owner. Public profile gates
repeat native membership, nonce/directory rejection, timing and source/user/config
snapshots before and after execution. Mail and optional remote URL integrations
are disabled by owned lab configuration and remain unqualified.

## Two confirmed owner defects

The canonical original run `20261116T224434-dd4823` passes native prerequisites,
then all five public calls fail to retrieve a nonce. The configured actual page
returns 301, which the original discovery ignores. The repair follows at most
three same-target redirects using the existing HTTP normalizer while preserving
the operator's mapped endpoint and virtual host. Foreign hosts, schemes,
credentials and unrelated explicit ports are rejected. Existing 404 nonce parsing
is preserved, unreachable/missing nonce failures are explicit, inverted page
bounds fail clearly, and nonces remain fresh. Candidate
`fca0de00f8b10d9bbc2192e6942a3ac7ab51ee99` is imported as
`2301ca96177bea80b7df16320bf977ae83c70b92`.

An intermediate repaired run recovers correct native data but exposes an
incorrect service-label assertion and cascading loot bookkeeping in the new
harness. Both harness issues are corrected before the final original replay.
Their failed evidence is retained and adds no accepted coverage.

With that corrected harness, nonce-only run `20261116T224849-be0ae0` has two real
failures. The first extraction persists one incorrect hash byte; the repeat
recovers the right hash and consequently creates a second private credential.
Four captured target queries have syntax errors at randomized derived-table
aliases: `982E2`, `6e5W2`, `5e88N`, `4E0y1`. The `6e5W2` error occurs at the exact
true predicate whose lost delay changes native character `7` (ordinal 55) into `5` (ordinal 53).
The callback is identical before and after the nonce fix: this is a second
pre-existing defect.

Forty independent genuine HTTP controls reproduce all four rejected raw aliases;
backtick quoting and an underscore prefix each restore the four real members
and expected timing. Zero and negative scalar controls work, rejecting a
separate zero-scalar hypothesis. The narrow repair backtick-quotes the existing
random alias, preserving the random scalar, inner payload and all options.
[MariaDB identifier rules](https://mariadb.com/docs/server/reference/sql-structure/sql-language-structure/identifier-names)
explain numeric/exponent ambiguity and identifier quoting. Candidate
`594dfe1aa633755b815b9593f617946a556f2cba` is imported as
`6cc199d20ec33c5b87d074b43d0d83ae8c109559`.

Final root run `20261116T231448-dda867` passes all five cases. Its 58 declared
inputs match both the canonical original and nonce-only failing runs with only
the owner changed. This separates both owner defects from setup and harness
mistakes. An earlier missing-archive manifest error starts no containers or
module calls and also adds no coverage.

## Accepted public matrix

Every profile has zero failures, pending cases and outside errors:

| Profile | Cases | Accepted run | Result |
| --- | ---: | --- | --- |
| [ultimate_member](ultimate_member/README.md) | 5 | `20261116T231448-dda867` | Two complete extractions with stable IDs, missing directory, missing nonce, closed port |
| [ultimate_member_subdirectory](ultimate_member_subdirectory/README.md) | 1 | `20261116T233000-9a30ab` | Actual /wordpress install and complete hash |
| [ultimate_member_prefix](ultimate_member_prefix/README.md) | 1 | `20261116T233502-64ad77` | Actual wp_native_ tables and complete hash |
| [ultimate_member_plain](ultimate_member_plain/README.md) | 1 | `20261116T234036-b52c34` | Native plain permalinks and complete hash |
| [ultimate_member_count2](ultimate_member_count2/README.md) | 1 | `20261116T235039-bfe3ec` | Two complete native credentials |
| [ultimate_member_default_bounds](ultimate_member_default_bounds/README.md) | 1 | `20261116T234536-268e9f` | Unmodified page/directory discovery bounds and complete hash |
| [ultimate_member_fixed](ultimate_member_fixed/README.md) | 1 | `20261116T232350-9bd74a` | Fixed 2.8.3 refuses extraction |
| [ultimate_member_inactive](ultimate_member_inactive/README.md) | 1 | `20261116T232517-ed8618` | Installed inactive plugin refuses extraction |
| [ultimate_member_absent](ultimate_member_absent/README.md) | 1 | `20261116T232630-afe114` | Absent plugin refuses extraction |
| [ultimate_member_no_custom_meta](ultimate_member_no_custom_meta/README.md) | 1 | `20261116T232738-552377` | Native standard metadata path refuses extraction |
| [ultimate_member_empty_roles](ultimate_member_empty_roles/README.md) | 1 | `20261116T232848-fe8975` | Default empty role selector refuses extraction |

These fifteen public runs include **seven positive calls and eight refusals**.
Seven deduplicated complete 63-byte native hashes persist across six positive
profiles, with correct endpoint, WordPress service, private type and module
origin. Repetition preserves credential/service IDs. Seven exact loot files
contain eight complete records, and six deduplicated findings persist. Source,
users and configuration remain identical. All final logs have zero SQL errors.
No HTTP, SQL, target-protocol or reporting doubles are used in these functional
cases. Jobs and sessions finish empty. The 164 native gate requests are target
validation, not extra functional cases.

## Verification and limits

The nonce regression suite has 29 owner examples: 26 original failures become
zero repaired failures. The alias suite has 16 examples: 10 nonce-only failures
become zero final failures. Parent combined invocation passes 52 examples:
45 owner cases and seven autoloaded support cases. Transport/discovery, SQLi
factory/probe, UI, Framework and reporting doubles are explicitly identified in
the unit suites. Captured fixture substrings are verified against exact native
source bytes; synthetic alias inputs are labelled. Genuine SQL execution and
extraction are established separately by native/public runs above.

All five changed Ruby files have zero RuboCop offenses and full owner msftidy
passes. Shell syntax and the source inventory pass. The inventory has 5,179 source
files, 272 registered owners, 490 manifest profiles, 29 individual reviews and zero
stale reviews. Registration alone is not accepted runtime coverage; the historical
qualified totals at this checkpoint are 271/487/3,678.

All 88 consumed paths match runtime evidence: 86 tracked blobs match source/fixture
commit `db7f0891cf3486705de8e05b256331f71a4953fd` and two ignored official ZIPs match the catalog.
Runtime receipts retain their actual earlier Git revision and working-input
hashes. The complete human module guide and Scenarios remain unchanged:
SHA256 `fc6690ce7e8af45b32a8ab3320868bdec3a0daeafca5245d71963cf03288d836`.

Positive tests request one user, except explicit COUNT=2, using SqliDelay=0.6.
Complete blind extraction takes several minutes; timeouts permit the full value
rather than accepting partial data. Complete modern `$wp$2y$` hashes retain null
`jtr_format` through the existing shared classifier; cracking-format selection
remains a separate follow-up. Multi-target Scanner fanout remains unqualified
because the owner overrides `run`. Other plugin/runtime/database versions,
external integrations and HTTPS deployments remain unqualified.

One stack runs at a time with three capped containers: app 1 CPU / 512 MiB,
MariaDB 0.5 CPU / 512 MiB and PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory, PIDs are limited to 128,
init is enabled and published ports bind loopback. The work-container maximum
is three. Unrelated connector startup briefly raises the observed global count
to five; the watcher removes all four unrelated containers. Four more connector
containers appear on reconnect and are removed under the user's cleanup policy.
No unrelated image or volume is pruned. The final audit independently confirms
all 55 attached volumes/networks absent, all projects/global containers empty,
the advisory lock free and no campaign Ruby process. All 132 OOM/PID snapshots
have zero events. The final batch finishes naturally with exit 0.

All 967 final runtime entries are independently rehashed. The
**40-entry** qualified seal references
**28 exact seals / 1867 independently rehashed entries**:
`/Users/dwelch/.codex/reports/ultimate-member-qualified-checkpoint-20261117`,
manifest SHA256 `9264f26adb1931c563240cc46ddc6f9575e56c489dbdd8779c3314600e66829d`.
It retains prerequisite, original, harness, corruption, native-counterfactual,
worker, final-runtime and prior-publication CI evidence. The separate
[publication follow-up](VERIFICATION-20261116-publication-followup.md) records
Brother native failures and Secure Copy's upstream-checkout Linux Mettle timeout
without assigning an unverified cause or adding local cases.
