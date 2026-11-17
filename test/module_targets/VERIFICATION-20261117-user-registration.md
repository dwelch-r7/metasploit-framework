# User Registration membership RCE qualification — 2026-11-17

This checkpoint adds one owner, four qualified profiles and nineteen public
cases, reaching **276 runtime owners in covered paths, 527 qualified profiles
and 3,791 historical functional cases**. All four profiles pass in one serial
invocation. The broader campaign remains active; no PR is created.

Owner: `exploit/multi/http/wp_user_registration_membership_escalation`.
The human guide's version bounds and setup prerequisites are corrected; its
historical Scenarios remain byte-for-byte unchanged.

## Genuine targets and independent controls

Unmodified official Free 4.1.1 and fixed 4.1.2 archives run on pinned WordPress
6.8.3, PHP 8.3.28 and MariaDB 11.2.2. All 1,225 files per distribution match the
release catalog. The [WPScan advisory](https://wpscan.com/vulnerability/2c0f62a1-9510-4f90-a297-17634e6c8b75/)
and vendor source establish exclusive fixed bounds: Free 4.1.2 and Pro 5.1.2.
Official source tags in [themegrill/user-registration](https://github.com/themegrill/user-registration)
resolve to `d1caa7f0768ae2f1ca5a6c36394c1821bbf3b93b` and
`51d35f8f1c3c5c146af18ad91f8daf51eb1ad694`. Primary tag/source receipts and the
distribution comparisons are retained. Commercial Pro is not installed.

Vendor onboarding creates the real free subscriber plan, membership form and
public pages. All PHP bootstrap APIs run as the web worker. The ordinary
MariaDB role is `module_target@%` on `wp_root`; the isolated reporting PostgreSQL
role is also nonsuperuser. No vendor endpoint or authentication code is patched.

Before Framework execution, native prototypes verify registration, the actual
role, password login and administrator permissions. Affected 4.1.1 promotes the
new subscriber and permits a benign genuine plugin upload plus PHP/shell UID-33
execution. Fixed 4.1.2 returns membership JSON success but retains Subscriber,
returns 403 for the admin page and refuses upload. A bounded app-to-host token/ACK
proves basic callback reachability independently. Native cleanup deletes only
the owned plugin/account/order/subscription records. The expanded prototypes
make twelve/nine HTTP requests, collect eight zero resource snapshots each and
remove all four attached objects per two-container stack.

Three excluded native harness attempts remain preserved: a boolean hook-presence
assertion incorrectly expected a numeric priority; root bootstrap produced an
unwritable upload directory; and native plugin deletion omitted a required
WordPress include. Real upload errors exposed the fixture ownership defect.
The corrected setup uses the genuine web identity and native APIs. These failed
attempts do not establish owner defects or successful native restoration.

## Original public outcomes and repair

Original `20261117T090514-95f52c` has five examples: one PHP failure, three pending
cases and one outside hook error. Public check succeeds. The owner genuinely
registers/promotes an account, authenticates, uploads and executes PHP, but five
Meterpreter connections die without a verified usable session. The console is
confirmed alive when its prompt times out. Remaining cases are skipped after
contamination is detected; residual plugin removal relies on stack teardown.
Both independent native phases still pass. The failure and complete raw evidence
are retained rather than counted as qualification.

The captured 63,979-byte uploaded PHP, SHA256
`68cd187459997e704ace6720c23a4d3452bc4d8d2a26c94a5070f6944363c5d9`,
reconstructs exactly from installed payloads 2.0.257 and its actual configuration.
It is a single payload with no embedded extension, not a staged wrapper or
corrupted upload. A separate Unix split passes check and two real shell sessions.

That original execution also exposes a distinct owner defect: credentials remain
Untried with a null attempt time after genuine password authentication and admin
upload. Repair `24fc81c9ce9` keeps initial Untried creation, then updates the same
credential core's login after either authentication path succeeds. It records a
Time timestamp without inferring access level from the membership JSON. Failed
authentication and inactive-database behavior remain covered. The same 22 focused
examples produce twelve failures before and zero afterward. These use the real
owner/parser with disclosed HTTP/authentication/payload/reporting doubles; they
are separate from functional qualification. Syntax, RuboCop and msftidy pass,
and parent review verifies all three imported source/capture files.

Explicit `EXTENSIONS=stdapi` PHP comparison `20261117T092610-1d3009` passes three
cases, including two real typed sessions and cleanup. Reading each session's
actual cached EncodedPayload retains its already-used bytes without regeneration.
Both 142,638-byte captures contain exactly one extension group with the exact
58,983-byte installed stdapi source, SHA256
`f7cd2a58ee586e666bf414444a69eede9cd1308a3ac4054138822d7861b78402`.
Actual callbacks/timeouts match the public options. Full cached strings also
reconstruct exactly. Dynamic extension bootstrap and the previously reproduced
framing fault remain a concrete candidate for investigation; historical wire
causation is not established. This comparison includes the reporting-only owner
repair. It does not qualify the missing-extension or installed staged paths,
and no module default or dependency is changed to hide their limitations.

## Final public qualification

Tested revision: `15d93c64e87034a6351265df2c7609feb92994ef`.
Run: `20261117T093315-b5b12d`, aggregate CLI exit 0, nineteen examples passing,
zero pending cases and zero outside errors. All 99 unique declared inputs match
the final bytes; all 97 tracked inputs match the tested revision.

| Profile | Cases | Native HTTP | Test seconds | Real sessions |
| --- | ---: | ---: | ---: | ---: |
| Affected 4.1.1, repeats, no AutoCheck and duplicate username | 7 | 39 | 168.5 | 5 |
| Affected below `/portal` | 5 | 36 | 111.4 | 4 |
| Affected with native core WordPress login enabled | 5 | 36 | 113.0 | 4 |
| Fixed 4.1.2, Safe check and automatic refusal | 2 | 18 | 34.2 | 0 |

Thirteen typed sessions prove execution as UID 33: six PHP Meterpreter sessions
with explicit embedded stdapi and seven Unix shells. Every created account also
passes independent native password and administrator-page checks. Six exact
credential/login pairs have the correct service, endpoint, password and origin,
Successful status and a bounded attempt timestamp. Repeated executions preserve
core/login IDs. Sixteen scoped findings and thirteen exact credential loot files
are verified. Duplicate-user rejection leaves the existing subscriber unchanged.

Repeats use the same selected console module and username, with newly created
native user IDs after test-owned cleanup. Framework creates distinct internal
exploit clones; UI object equality does not prove reuse of runtime instance state.
FileDropper removes each successful run's uploaded plugin. The test then removes
only its owned account/orders/subscriptions and execution proof. Selected original
users, hashes, roles, user metadata, membership rows, configuration/forms and
vendor/plugin files compare equal afterward. Auto-increment growth and filesystem
free-space metrics are excluded; complete database restoration is not claimed.

Both native phases pass in every profile. The 129 HTTP controls and 48 cgroup
snapshots have no OOM or PID-limit event. Actual inspect data confirms healthy
services, matching memory/swap caps, CPU/PID caps, init and loopback publication.
Only one stack and at most three containers run at once. All twenty final attached
volumes/networks are individually absent, and global container inventory is empty.
No unrelated container is observed in the final cohort; unrelated images and
volumes are not pruned.

## Reproduction and retained limits

See the [component guide](user_registration/README.md) for archive preparation,
the four-profile serial command and prerequisites. The Compose definitions live
alongside the fixture under `test/module_targets`; the human module guide links
to that reusable setup. Native and diagnostic split cases add no qualification
counts. Commercial Pro, Windows, other plugin/core/PHP releases, TLS, multisite,
disabled/renamed membership routes, plain permalinks and forced fixed-target
execution remain unqualified. PHP default/transport limitations remain in
[the deferred ledger](DEFERRED.md).

Read-only parent checkpoint:
`/Users/dwelch/.codex/reports/user-registration-qualified-checkpoint-20261117`,
manifest SHA256 `e2522a17e02d50b65d13e3391bb166458d66b98623b9e4032f35fdfc86c81907`.
Its ten entries reference fifteen independently rehashed seals containing 1,454
exact entries: native readiness and excluded harness attempts, original public
failures/splits, the worker repair, passive payload analysis and all final profiles.
Console/HTTP evidence, exact source/archive bytes, database rows, resources and
individual cleanup queries are retained. Unit examples and native probes are
counted separately. CI for previous publications does not establish CI completion
for this checkpoint.
