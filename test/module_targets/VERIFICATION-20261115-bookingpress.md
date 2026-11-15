# BookingPress credential gathering investigation, 2026-11-15

Runtime qualification is pending. This record adds no owner, profile or case to
the published Erlang SSH checkpoint of 256 owners, 379 profiles and 3,291 cases.

## Genuine target controls

The fixture installs official BookingPress 1.0.10 and 1.0.11 ZIPs into genuine
WordPress 5.2.4 / PHP 7.3.11 with MariaDB. Their SHA256 values are
`81fa8ee3a1b9f1df8bfbcc78799f33eb1ad673be8811d8610e7856daa73716fb`
and `5fa4be8671510ab5bf59ee845f1db40ca8f615e7cc357944759991f7dfbd0988`.
The [original disclosure](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357/)
and the official release sources identify the 1.0.11 prepared-integer fix.
No vendor PHP or database response is replaced.

Vendor activation creates the schema. Ordinary owned category 7 and service 11
and a published `[bookingpress_form]` page satisfy the documented prerequisites.
Independent HTTP controls verify the real service lookup, invalid-nonce
rejection and a UNION scalar. Affected targets disclose exact native
username/email/hash collections; fixed targets refuse the same requests while
ordinary lookup remains healthy. Before/after target snapshots agree.

All four standalone native controls pass: affected root, fixed root, affected
`/wordpress` installation and affected custom `bp_` database prefix. Their four
seals contain 264 independently rehashed entries. Live inspections confirm two
capped containers during these native-only probes; all six independent cleanup
queries per attempt pass. These probes make zero owning-module calls and add no
functional qualification.

## Preserved original results

All original public runs below use production source SHA256
`7346aad48905c9c3c5ef85ba8d4be9479c1b7eeb124c8c10ccf82d0c68d5b9e6`.
The whole human module guide, including Scenarios, remains unchanged.

The first root run reports six cases / two failures. Both failures are fixture
expectations: Framework's `report_service` lowercases saved service names, while
the test expected mixed case. Each reached credential run genuinely extracts
and saves all four exact native hashes, with correct username, address, port and
module origin, and prints their emails. The expectation stops each repeated
success case before its second call. The actual eight owning calls and all
native before/after controls are retained. The 123-entry archive has manifest
SHA256 `09dd364f2d4481e6eeea50e8240f70b5445043333c5c103533838c7e9014f4f6`.
The corrected expectation follows the real reporting implementation; this is
not classified as a production defect.

The genuine subdirectory run reports six cases / three failures and seven
owning calls. Native injection succeeds at
`/wordpress/wp-admin/admin-ajax.php`; the owner instead posts to the root
`/wp-admin/admin-ajax.php` and receives 404. Its deferred SQLi callback then
raises `LocalJumpError: unexpected return`. All credential snapshots are empty.
The 124-entry archive has manifest SHA256
`61cf27ccf6307c4a92cc8b8c76a5e243308901d9d72ce6df2c217e51ce4cb64b`.

On genuine fixed 1.0.11, the original module reports three cases / three
failures and three owning calls. The legitimate empty JSON array leads to the
same deferred nonlocal-return exception instead of a valid check result or
bounded run failure. Native ordinary lookup and fixed injection refusal pass
before and after; no credential is saved. Its 121-entry archive has manifest
SHA256 `36f73b3b851e49e59a10491aa9aac6dec1cd9f7a5770258508163015ab9be6c7`.

The custom database prefix run reports six cases / three failures and seven
owning calls. Native requests retrieve all four exact users from `bp_users`.
The owner's hardcoded `wp_users` bootstrap and dump produce three direct
unknown-table entries in the real application log, followed by the callback
exception. All credential snapshots are empty. The 124-entry archive has
manifest SHA256
`377f30b341615566c0d7aa186791167932f97b1ca03d3d45c15685f4a7605bfd`.

The low-limit run reports six cases / two failures and eight owning calls.
Independent target inspection reads the real `group_concat_max_len` as 96;
native per-user queries retrieve all four complete records before and after.
Both reached owning credential runs report normal completion but truncate the
collection. PostgreSQL saves one complete administrator hash and incorrectly
saves `module_author` as `Metasploit::Credential::BlankPassword`; the other two
users are missing. The printed author email is also truncated. This is genuine
silent credential corruption, not an expectation or display-only defect. The
124-entry archive has manifest SHA256
`19772dfda9031a3cbc38541168015c7858c63e56031a6450a90b7e81c233db5f`.

Each completed public attempt independently confirms all selected containers,
networks and volumes removed and the global advisory lock released. A separate
worktree owns the scoped source repair and focused regression tests. The primary
worktree owns all Docker and functional execution; only one heavy lane is used.

## Remaining work

The source repair comparison and final public profile replay remain in progress.
No passing repaired behavior is claimed here. The eight-profile final replay
plans 37 cases, including ordinary page-ID query URLs, an absent plugin and an
unrelated service alongside the deployments above. The lab keeps at
most three capped containers, uses the existing local console bundle and removes
each stack before starting the next. No PR is created.
