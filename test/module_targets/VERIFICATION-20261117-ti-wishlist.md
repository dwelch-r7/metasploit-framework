# TI WooCommerce Wishlist qualification — 2026-11-17

This checkpoint adds one owner, nine qualified profiles and thirteen public
cases for `auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli`, reaching
**274 runtime owners, 517 qualified profiles and 3,751 historical functional
cases**. Seven profiles retain their exact earlier inputs; two targeted replays
pass after an option repair and conservative delay configuration. The original
aggregate remains failed. The module has no public `check`. The existing human
module guide and its Scenarios are unchanged.

## Genuine target and native proof

Official Wishlist 2.8.2 and fixed 2.9.0 archives run with WooCommerce 9.3.3,
WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2. Native WordPress installation,
plugin activation, schema and real published product creation precede testing.
Vendor code is unmodified; all 4,609 catalogued vendor files are hashed against
the pinned catalogs. The ordinary database role is `module_target@%` on `wp_root`.
Four native users retain complete modern 63-byte password hashes.

Before public module execution, independent HTTP requests verify the login,
home and product pages, real guest wishlist creation, benign REST product data,
and paired false/true timing predicates including a complete native user row.
Three pairs at a 0.5-second delay qualify affected 2.8.2; the same probes show
no timing signal on 2.9.0. The latter release's official source introduces an
`ASC`/`DESC` order allowlist. An earlier 0.2-second native calibration fails its
timing margin and is retained without a module verdict. Its source, product,
role and ordinary API gates work; no Framework call occurs in that calibration.

The independently qualified native affected and fixed attempts each retain
nineteen pre-start inputs, eighteen HTTP requests and eight zero OOM/PID-limit
snapshots. Their separate 60-entry seals have manifest SHA256 values
`7dd6d80bff6ae9fb6b936dc93496a6c130a4a341f26dbbef97adc7dba9909754`
and `c8d4399237ac4b19fa8e1f0a845ea7ff4a41ca805b8bb5dba1325f74ef79a947`.
These native probes add no Framework functional qualification.

## Preliminary public results

The one-case affected baseline `20261117T054606-4254da` passes. Its public run
takes 258.7 seconds and returns the exact native username and full password
hash, a persisted credential with the correct origin/endpoint, a vulnerability
record and an exact loot file. Thirty-four independent native HTTP requests,
twelve zero OOM/PID-limit snapshots and after-state checks pass. Original users,
usermeta, vendor source, configuration and product are preserved. Guest wishlist
rows remain until stack teardown; complete database restoration is not claimed.
The credential's cracking-format field is null, retained as a separate reporting
limitation already observed for modern WordPress hashes in other owners.

The 101-entry baseline seal is
`/Users/dwelch/.codex/reports/ti-wishlist-ti_wishlist-20261117T054606-4254da-seal`,
manifest SHA256 `7802340e8c0484a1e96477940d04ed4e1eb57d41df1f7ddaea1820576ffd1f1c`.
This preliminary case will not be counted again in the final matrix.

The four-profile batch `20261117T055240-47031f` exits 1:

| Profile | Public cases | Observed result |
| --- | ---: | --- |
| Fixed 2.9.0 | 1 | Pass: genuine fixed source refuses extraction; native before/after gates pass |
| Inactive | 0 called | Harness gate fails: native deactivation leaves sparse plugin-option indexes, serialized as an object |
| Absent | 1 | Owner fails with `NoMethodError` at `get_share_key`, after independent native preflight passes |
| Empty catalog | 1 | Pass: native empty product response produces a bounded NotFound refusal |

The initial inactive failure is a diagnostic representation assumption. Its
original native option is retained, and the control now also exposes
`array_values` for membership comparisons. The original-owner replay
`20261117T060152-90cfe4` passes those corrected gates, then independently
reproduces the same `NoMethodError` as the absent profile. Both native before
and after gates pass, with eight HTTP requests and twelve zero resource
snapshots. Its separate 102-entry seal has manifest SHA256
`950e03fcae208d527eb21a51f2d433dac318a86fc9604d15e2ec9417f0d26aa8`.
All five attached objects and the global container inventory are empty afterward.

The absent owner failure is separate: a healthy WordPress HTML response becomes
an empty JSON document, then the module dereferences missing `wishlists_data`.
The returned console exception, native after checks and twelve zero resource
snapshots are retained. A separate worktree's narrow response-shape repair in
`8552c27e9571797d4f6a81a35c907fd990fc8769` preserves genuine associative
product collections. Identical focused contracts produce 36 examples with
nineteen failures on the original and zero on the candidate, seed 63419; these
include seven support examples. Related owner/prefix contracts pass 56 examples
with zero failures. Baseline and final owner lint/msftidy pass. The transport,
Framework/UI objects and malformed variants in these contracts are doubled;
the multipart builder and Rex JSON parser run intact over captured native JSON
and a disclosed native HTML prefix. Subsequent inactive and absent public
replays pass as recorded below.

The parent independently rehashes the exact 42-entry worker seal at
`/Users/dwelch/.codex/reports/ti-wishlist-response-contract-fix-20261117T060347Z-seal`,
manifest SHA256 `abc14432963066c65c945bd1efea98cbbad6a4c1fae3c99db8093c72c82f5623`.

Each profile has its own sealed inputs, raw console/HTTP evidence and cleanup
audit. All four projects and twenty attached volumes/networks are removed and
individually verified absent. Each stack stays at three capped containers;
the final global inventory is empty. No image pruning, PR, CI retry or CI
cancellation is performed. The broader campaign remains active.

## First complete matrix: two failures retained

Committed fixture `b1a760881c1` runs all nine profiles in one serial invocation,
`20261117T060523-140d2e`. Its aggregate CLI exits 1. Seven profiles pass eleven
public cases: inactive, absent, fixed, empty catalog, the five-case default
profile, subdirectory and plain permalinks. The repeated default extractions
take 259.3 and 263.9 seconds on the same console module object, preserve credential
IDs and create two exact loot files. All seven include passing native after
checks and cleanup. No all-green aggregate or new campaign count is claimed.

The custom-prefix case passes native before/after gates but recovers byte five
of `wp_native_` as `0x80` instead of `a`. It subsequently queries a nonexistent
table, reports zero credentials and saves an empty loot. The full-data assertion
fails. Reconstructing all eighty captured prefix-character comparisons identifies
one disagreement with the native prefix: the `>127` comparison for byte five
takes 727,578 microseconds on the server, exceeding the configured 0.5-second
cutoff. The bisection therefore follows the upper branch and returns `0x80`.
The captured encoded SQL and all raw bytes are retained; independent evaluation
of that exact predicate is recorded in the frozen proof below. This is separate from reserved alias
grammar: the actual alias is quoted `kc`, and the query returns nine other prefix
bytes correctly. No wall-clock change is needed to explain the observed branch.

The two-user case takes 511.3 seconds and reports `Unknown datastore option:
COUNT`. The owner reads that datastore value but never registers its option.
Independent comparison of the returned credential rows also finds one wrong
byte in the administrator hash: offset 49 is `x` instead of native `u`; the
author hash matches. The test does not accept these rows. Its native after check
additionally records a false response taking 0.545 seconds, beyond the short
delay's safety margin. This original attempt remains unqualified for both reasons.

All nine original attempts are sealed before changing fixture parameters.
All 45 attached volumes/networks are individually absent and the global Docker
inventory is empty before transferring the lane to the native investigation.
The original seal index is retained in
`tmp/ti-wishlist-feasibility/public-trial-20261117T060518/seals.json`.
Subsequent work must distinguish the option-registration repair, conservative
delay configuration and unchanged original results. The seven passing profiles
retain their exact `b1a760881c1` inputs; targeted replays of the two failures are
recorded below. The broader campaign remains active.

## Targeted repair and delay qualification

The COUNT repair `30a5bebbe7630a18e8ae2de419c3679fe39d0a9a` registers the
existing setting as an optional integer and keeps its default of one. The
duplicate metadata default is removed. Zero still follows the shared MySQL
helper's existing all-rows behavior. Same-seed tests produce 42 examples with
four failures on the predecessor and zero after the repair, seed 29761:
35 owner contracts and seven support examples. They include the actual console
option validator, integer normalization, noninteger rejection and preserved
defaults. Changed owner/spec lint and module msftidy pass. Public `COUNT=2`
replay passes as recorded below.

The 27-entry COUNT repair seal is independently rehashed at
`/Users/dwelch/.codex/reports/ti-wishlist-count-option-registration-20261117T070247Z-seal`,
manifest SHA256 `8a401e95900d573a7f828caef0cdaea69c0b79ca5f7827bfdc69e2366d3c20ef`.

The two original corruptions have independent request traces. All eighty prefix
and 1,232 credential-character comparisons are reconstructed from captured
requests. In each set one comparison disagrees with the native data, and every
inferred client branch agrees with the server duration crossing 500,000
microseconds. For the administrator hash, global character 63 is native 117
(`u`), but its `>119` comparison takes 699,682 microseconds, selecting the branch
that ultimately returns 120 (`x`). These observations do not identify the source
of the slow server responses or justify a production bisection/timing change.

The frozen native replay `run-20261117T065359Z` independently executes the
exact captured literal and encoded prefix queries as the ordinary database
role. Both return `wp_native_`; byte five is 97, `>127` is zero and `>96` is one.
Three HTTP false/true pairs at each delay pass: median 0.185/0.640 seconds at
0.5 and 0.144/1.125 seconds at 1.0. Nineteen HTTP requests, eight zero resource
snapshots, two capped containers and four individually absent attached objects
are retained. Twenty-nine inputs are verified before startup; all twelve runtime
bind files are frozen from the recorded `b1a760881c1` inputs.

The first proof run is excluded because the parent changed a shared diagnostic
file during its after gate. Two further frozen-controller startup failures
(executable mode and Compose dollar escaping) reach no SQL/HTTP proof and are
retained separately. The final exact 300-entry seal is independently rehashed at
`/Users/dwelch/.codex/reports/ti-wishlist-prefix-native-proof-20261117T065923Z-seal`,
manifest SHA256 `a4cf789a01101dd41db350d4d5489270b7765baa18f9d4838b8b4465b5748958`.
This native proof adds no Framework cases.

The two failed profiles now select Framework's existing one-second delay,
exceeding the observed slow false responses. Their independent HTTP gates use
the same setting. The prefix case also evaluates the captured lookup and byte
predicates directly in MariaDB and over HTTP. The other seven profiles retain
the earlier half-second setting and their exact tested revision. Their default
COUNT remains one; the fixture's new delay/timeout parameters preserve the old
defaults. These changes precede the two-case public replay below. The original
failed aggregate remains retained.

## Qualified public replays and retained source revisions

The two-case invocation `20261117T070436-1eb146` exits 0 with no failures,
pending cases or outside errors, using clean committed fixture
`f602bc60b23d00715464d58b201cccf085189dcd`. The prefix call takes 472.7 seconds
and returns the exact complete native row. The two-user call takes 817.9 seconds,
recognizes COUNT without a console warning and returns both complete native
hashes. Each saves exact loot and correct scoped credentials/findings; all
independent native before/after checks pass. The prefix controls include the
actual encoded lookup and independently evaluated byte predicates. The one-second
setting is validated for these cases; the original latency source is unverified.

The qualified cohort consists of eleven passing cases from seven profiles at
`b1a760881c19756f577460bebeba0d31ae4d04a6`, plus those two current replays.
The production delta between the revisions is exactly COUNT registration and
default deduplication. Its integer default remains one, verified in focused
contracts and the new default-count prefix run. The common fixture's delay and
command timeout retain 0.5/900 defaults for the earlier seven; only the two
replays choose one second, and COUNT=2 allows a 1,200-second command bound.
Earlier profiles do not have identical current input bytes and are not presented
as a new all-green thirteen-case invocation. Their archived input bytes match
their exact tested Git revision; the two replays also match current bytes.

The parent independently verifies all thirteen returned public calls, both
complete-row results, repeat module identity and credential deduplication,
native before/after identity, report scope, loot contents and actual Docker
inspection limits. The selected cohort has six deduplicated credential cores,
five findings, six exact loot files, 238 independent native HTTP requests and
108 zero OOM/PID-limit snapshots. Seven complete user rows are extracted across
six successful calls; one row is a repeat. Qualified profiles have 45 attached
objects individually absent. Including both original failed profiles, the full
original matrix and replays remove 55 attached objects. Both local Docker
contexts resolve to one empty engine. Images and unrelated volumes are retained.

The prefix replay's 108-entry seal has manifest SHA256
`fdef5de86f173c83f47d44f21a45bd1f448ce86e55b65bf2782275adbf7a005a`;
the two-user replay's 110-entry seal has manifest SHA256
`9d6bd196e2467d5a3fe3514b4bc4ebbc5ba5fd2c3317110076ac6cbb7e613bda`.
All nine selected profile seals, their complete 1,076-entry payload sets and
recorded Git source blobs are independently verified. The 18-entry parent
checkpoint is `/Users/dwelch/.codex/reports/ti-wishlist-qualified-checkpoint-20261117`,
manifest SHA256 `fe2f538b92d80fa1b0b40d15553b36e0e7912aeb2b81696c003ff25c2a0944f5`.
It references fifteen immutable seals, keeping failed attempts distinct from
qualification. Preliminary/native-only attempts add no cases.

## Review and remaining scope

**Summary:** Reusable Compose targets and public automated tests qualify the
selected owner behavior. Response-shape and COUNT declaration defects are
repaired; the shared prefix alias fix has separate native/unit evidence.

**What looks good:** Independent real application/data gates, full modern hashes,
reporting and repeat checks prevent banner-only or exception-only success claims.
Original failures, configuration drift and bootstrap failures remain preserved.
Changed Ruby lint and owner msftidy pass. No PR is created.

**Concerns:** The initiating server-latency cause remains unknown. Null modern-hash
cracking-format metadata is unchanged. Other releases, core/PHP combinations,
TLS, multisite and COUNT=0 functional extraction are not qualified here. No
universal timing-reliability claim is made.

**Suggestions:** Keep these operational limits visible and continue the broader
module campaign; the next WooCommerce Payments candidate has source review only.
