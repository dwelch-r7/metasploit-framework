# TI WooCommerce Wishlist validation — in progress

This work is not yet added to the campaign totals. The planned matrix has nine
profiles and thirteen public cases for
`auxiliary/scanner/http/wp_ti_woocommerce_wishlist_sqli`. The module has no public
`check`. The existing human module guide and its Scenarios are unchanged.

## Genuine target and native proof

Official Wishlist 2.8.2 and fixed 2.9.0 archives run with WooCommerce 9.3.3,
WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2. Native WordPress installation,
plugin activation, schema and real published product creation precede testing.
Vendor code is unmodified; every installed vendor file is hashed against the
pinned catalogs. The ordinary database role is `module_target@%` on `wp_root`.
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
and a disclosed native HTML prefix. Native public replay of the repair is pending.

The parent independently rehashes the exact 42-entry worker seal at
`/Users/dwelch/.codex/reports/ti-wishlist-response-contract-fix-20261117T060347Z-seal`,
manifest SHA256 `abc14432963066c65c945bd1efea98cbbad6a4c1fae3c99db8093c72c82f5623`.

Each profile has its own sealed inputs, raw console/HTTP evidence and cleanup
audit. All four projects and twenty attached volumes/networks are removed and
individually verified absent. Each stack stays at three capped containers;
the final global inventory is empty. No image pruning, PR, CI retry or CI
cancellation is performed. The broader campaign remains active.
