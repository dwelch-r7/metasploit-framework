# BookingPress credential gathering validation, 2026-11-15 to 2026-11-16

All eight genuine profiles pass **37 functional cases and 64 public module
calls**. Twenty complete credential dumps preserve every native username,
email and hash, including under a 96-byte aggregation limit. Forty workspace
credential rows match the independent target records. This adds one runtime
owner and eight profiles, advancing recorded campaign coverage to **257 owners,
387 profiles and 3,328 functional cases**. Earlier modules retain their recorded
inputs and scope; the broader feasible-module campaign remains open.

| Profile | Installed plugin / service | Deployment | Cases | Public calls |
| --- | --- | --- | --- | --- |
| `bookingpress` | 1.0.10 | Root installation, `wp_` tables | 6 | 10 |
| `bookingpress_prefix` | 1.0.10 | `/wordpress` installation | 6 | 10 |
| `bookingpress_table_prefix` | 1.0.10 | Custom `bp_` tables | 6 | 10 |
| `bookingpress_plain` | 1.0.10 | Ordinary page-ID query URL | 6 | 10 |
| `bookingpress_low_limit` | 1.0.10 | Real `group_concat_max_len = 96` | 6 | 10 |
| `bookingpress_fixed` | 1.0.11 | Genuine prepared-integer fix | 3 | 6 |
| `bookingpress_absent` | Not installed | Published unhandled shortcode page | 2 | 4 |
| `bookingpress_unrelated` | Genuine Apache | No WordPress or BookingPress | 2 | 4 |

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

## Scoped source repair and independent verification

The repair reads the genuine page's advertised AJAX path while retaining the
operator's configured HTTP transport. It handles empty, denied, missing and
malformed replies through typed failures; check returns reason-bearing results.
The bootstrap no longer requires `wp_users`, and existing WordPress helpers
discover the actual table prefix. Existing Common SQLi HEX encoding and per-row
extraction avoid aggregation truncation and field-delimiter ambiguity. Complete
rows are validated before credentials are saved, and every run refreshes nonce,
endpoint and SQLi state. The wordlist generator's machine-consumed discovery
comment is retained with the genuine plugin slug and fixed release.
The shipped scanner wordlist also adds that official archive directory while
retaining the legacy entry; the two pinned archives verify its exact name. This
small data correction adds no scanner runtime qualification.

The identical 40-case suite, seed 7721, reports **34 original failures and zero
repaired failures**, with no pending or outside errors. HTTP, reporting, UI and
the bounded SQL evaluator are doubles; the real Common SQL generation, HEX
decoding and WordPress prefix-discovery helpers execute. An initial reporting
double omission and a consistency correction to the synthetic old/new SQL
adapters are retained separately. These units add no runtime qualification.

The worker seal contains 226 independently rehashed entries, manifest SHA256
`7ac4e967de776d0cecea717a3c66e75cbe3b0767d303a0daf9ce19af244c0c34`.
Strict original/repaired lint, module tidy, syntax and the exact wordlist
consumer regex checks pass without baseline or new offenses. The primary
checkout independently passes **47 examples / zero failures**, including all
40 owner contracts and seven loaded existing datastore-formatting examples.

Final production source SHA256 is
`0e87f3d27c8485c8afd22a4240c56dae0e9598a7ffb73485d4a07915bcfcbd69`.
At fixture revision `1d6670bc872`, the repaired root profile passes all six cases
and ten public calls. Independent audit verifies four complete dumps, all four
exact native user hashes and emails, eight exact workspace credential rows,
native before/after controls, unchanged target records, all six cleanup queries
and lock release. Its 129-entry archive has manifest SHA256
`9de38c02cb8352e6ea712780a7cf9db91541a2334345cc4ab379d19992c3b5ef`.
The preliminary audit's accidental treatment of ordinary numeric service ID 11
as a HEX user record was corrected by inspecting the captured request form; no
runtime source or fixture input changed. Remaining profiles retain these same
frozen production and shared fixture inputs.

## Complete recorded results and setup correction

The next serial controller passes all six remaining WordPress profiles: 29
cases, 50 public calls, 16 complete credential dumps and 32 exact workspace
credential rows. Its unrelated profile stops before any owner call because
healthy Apache is attached only to the internal network and Docker supplies no
published port binding. The reporting database, attached to both bridges, has
its expected binding. This is a fixture network error, with no module result.
All 42 cleanup queries and lock release pass. The 347-entry archive retains
both the six successful profiles and the failed setup; manifest SHA256 is
`4254c8946e66b3e0c476487d4a4c019c55cdc8ba364bdc11a1a13caa4014687c`.
That controller's overall exit is 1 and is not presented as a passing aggregate.

Only `bookingpress_unrelated/compose.yaml` changes to attach Apache to the public
bridge, matching the existing unrelated HTTP recipes. All seven earlier passing
profiles' declared input hashes still match. At revision `8447f69f981`, the fresh
unrelated replay obtains a real loopback port, verifies the actual Apache marker
before owner calls, and passes both cases and all four calls. No credentials are
saved; both checks and enabled/disabled AutoCheck paths remain bounded. Its
123-entry archive has manifest SHA256
`53192087b256b5b44a45350cf855f9ac9b83997d23abcd9f26068059aa5888e2`.

Together the root, six serial successes and corrected unrelated replay cover
all eight profiles. Production source and shared executable inputs are identical.
Root and the six serial successes retain revision `1d6670bc872`; the unrelated
replay records its own revision above. The final lab README wording is updated
after execution and recorded as a documentation-only fingerprint difference.
No runtime result is substituted for another revision's executable inputs.

Each of the five affected profiles performs four successful dumps: two with
AutoCheck and two with it disabled, reusing the selected module within each
example. Repeated calls preserve complete rows and credential deduplication.
All four native account hashes and printed emails match each dump; both
credential workspaces retain the correct service, address, port, module origin,
hash type and format. Fixed, absent and unrelated controls save no credential.
Checks against missing pages and real PostgreSQL return reason-bearing Unknown;
runs stop with bounded failures without backtraces. The PostgreSQL invalid-startup log and subsequent successful queries
verify that the unrelated protocol request reached a healthy real server.

The final recorded paths include 107 independent native HTTP requests. Their
ordinary booking lookups, nonce refusals, UNION controls and exact per-user
reads remain separate from the functional counts. WordPress target identity and selected
user/category/service/page records agree before and after. All session/job
inventories are empty. An independent audit rehashes all 599 entries in the
three final runtime archives, compares every selected input and checks the
actual native response bytes, public output and PostgreSQL rows.

Every selected profile passes six independent cleanup queries: **48 selected
queries**, or 54 including the preserved failed unrelated setup. Exact container,
network and volume identities are absent; the global advisory lock is free and
the final global container inventory is empty. No OOM or PID-limit events occur.
Stacks run serially with at most three containers: app 0.5 CPU / 384 MiB /
128 PIDs, MariaDB 0.5 CPU / 512 MiB / 128 PIDs and PostgreSQL 0.5 CPU / 256 MiB /
128 PIDs. The unrelated app uses 0.25 CPU / 128 MiB / 128 PIDs and needs only two
containers. Memory-plus-swap limits equal memory limits. One local console uses
the existing bundle and avoids a fourth container.

Recorded RSpec durations are approximately 68, 68, 45, 42, 39, 28, 25 and 51
seconds in table order, including console/native setup and excluding image
preparation and Compose cleanup. No full local RSpec suite is run. Runtime scope
is the pinned linux/amd64 releases, one WordPress installation per stack and the
owned category/service/account data above. Other releases, PHP/core combinations,
multisite deployments and broader data populations remain unqualified. The whole
human guide and Scenarios are unchanged. No PR is created.

The final checkpoint seal contains 49 entries and references 14 preserved archives
whose 1,745 entries were independently rehashed. Its local identifier is
`bookingpress-qualified-checkpoint-20261116`; manifest SHA256 is
`039260c3213f2df49affae8e2e6ff5253d3da2ed6bc7d7ec0eed4b376b3a7804`.
