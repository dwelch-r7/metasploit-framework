# Pie Register RCE qualification, 2026-11-17

This checkpoint adds one owner, five qualified profiles and 25 public cases,
reaching **277 runtime owners in covered paths, 532 qualified profiles and
3,816 historical functional cases**. The broader campaign remains active;
no PR is created.

Owner: `exploit/unix/webapp/wp_pie_register_bypass_rce`, unchanged SHA256
`35218b83862418e8e61dce88713d08366417e4a41e9f0394e87e17e79c05231e`.
Tested fixture revision: `5d2254c794eb52a2e7e2d468b3bc40a308d8806c`.
The human guide links to the [reusable target](pie_register/README.md); its
historical Scenarios remain byte-for-byte unchanged.

## Independent target and version evidence

Unmodified official Pie Register 3.7.1.4, 3.7.1.5 and 3.7.1.6 archives run on
WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2. Complete archive/file catalogs
and CRC checks are retained. Nine independent official SVN source/readme files
match their distribution bytes. The CVEProject CNA record and
[WPScan advisory](https://wpscan.com/vulnerability/40d347b1-b86e-477d-b4c6-da105935ce37/)
are retained alongside source review. That advisory's malformed 3.1.7.6 metadata
does not override the actual source/runtime distinction below.

The numeric-ID path works on 3.7.1.4. Version 3.7.1.5 removes that path while
retaining a separate username bypass. Version 3.7.1.6 moves social authentication
behind an optional addon; no addon is installed. Public fixed-target refusal is
scoped to these fixture users and this owner's submitted numeric-ID request.
Accounts named `null` and social addons are not covered.

Bootstrap and native APIs run as the actual web worker, UID 33. Before and after
public calls, controls verify exact installed source/runtime, ordinary database
grants, real password authentication, WordPress cookie validation, administrator
permissions, genuine benign plugin upload and PHP/shell execution. A bounded
token/ACK exchange separately proves app-to-host callback reachability. Numeric
bypass, upload denial and the distinct username variant are checked independently
on the later releases. Cookie rejection is boolean false, not numeric zero.

## Original failure and fixture correction

The preliminary affected baseline passes five cases and four real sessions.
The original expanded run `20261117T110930-d9cc93` has actual CLI exit **1**:
four profiles pass sixteen cases, while root has nine examples, one failure,
one pending case and one outside error. Root opens five usable sessions; all
eight started public calls return and both native phases pass. Upload with
nonexistent USERID 424242 is correctly refused before payload execution.

The state comparison exposes exactly one extra selected row: session_tokens
metadata for absent ID 424242 with that call's exact user agent. Vendor code
calls wp_set_auth_cookie before get_userdata. Captured native core source shows
session creation persisting metadata before cookie generation; the metadata API
accepts a positive absent user ID. The original cleanup enumerates existing
users, so it misses this orphan. The contamination guard skips the zero-ID case,
and final restoration fails again. Disposable stack teardown removes the residue;
the failed profile does not claim successful selected-state restoration.

Fixture-only correction `5d2254c794e` observes the orphan, requires its reserved
absent ID, exact current nonexistent-case user agent, small token count and recent
timestamp, then uses the WordPress session API to remove it. Unknown metadata
still fails. The complete selected-state comparison is retained. The replay
removes exactly one owned orphan token and executes the previously skipped
zero-ID case. No production owner repair is established or applied.

## Qualified public replay

Run `20261117T112200-6defe3` has actual aggregate CLI exit **0**, 25 examples,
zero failures, zero pending and zero outside errors, all from the committed
revision above. All 100 unique declared inputs are
rehashed against their terminal bytes; tracked inputs match that exact revision.

| Profile | Plugin | Cases | Native HTTP | Test seconds | Real sessions |
| --- | --- | ---: | ---: | ---: | ---: |
| pie_register | 3.7.1.4 | 9 | 32 | 173.9 | 5 |
| pie_register_subdirectory | 3.7.1.4 | 5 | 32 | 109.1 | 4 |
| pie_register_plain | 3.7.1.4 | 5 | 32 | 111.0 | 4 |
| pie_register_fixed | 3.7.1.5 | 3 | 28 | 52.9 | 0 |
| pie_register_fixed_latest | 3.7.1.6 | 3 | 28 | 49.0 | 0 |

Thirteen typed sessions execute an independently verified UID-33 file proof:
six Linux PHP Meterpreter sessions with explicit embedded stdapi and seven PHP
command-shell sessions. Both families repeat with FileDropper cleanup; the root
also runs without AutoCheck. Subscriber, nonexistent and zero-ID requests refuse
upload. Later versions pass Safe checks, automatic refusal and forced refusal
for the selected numeric-ID path. Native authenticated upload still works there.

Repeats retain the selected console object; actual internal run objects are
distinct. Cached encoded Meterpreter bytes are read from the actual session's
exploit without regeneration and retained with their digests. Source establishes
that this owner's custom ZIP uses those bytes directly. An independent ZIP-body
capture is not claimed. The expected 10 scoped findings are
verified, with no credential or loot rows/files expected from this owner.

Selected users, password hashes, roles, sessions, user metadata, main plugin
options, pages, plugin-table rows and vendor/plugin files compare equal after
cleanup. Other WordPress options, usage counters, auto-increment growth and
filesystem free-space changes are excluded; complete database restoration is
not claimed. Public session/job state is empty after each profile.

The 152 native HTTP controls and sixty cgroup snapshots have
no OOM or PID-limit event. Actual inspect data confirms healthy services,
matching memory/swap limits, CPU/PID caps, init and loopback-published ports.
Only one stack and at most three containers run. All 25 attached objects are
individually absent after teardown. The original mixed cohort, native prototypes
and preliminary baseline add no further qualification counts.

## Compatibility, cleanup and remaining limits

The shared test HTTP helper keeps its original positional JSON interface and
adds opt-in form/raw bodies and headers. The existing WordPress batch root
regression passes ten cases and five real sessions with both native phases,
two independently compared exact JSON request bodies, twelve zero resource
snapshots and complete teardown. These regression cases add no new counts.
Changed Ruby syntax/RuboCop, the human-guide documentation check and diff checks
pass. Human Scenarios remain untouched.

Docker restart readiness is independently checked: the configured disk cap and
expanded virtual image are about 1 TiB, the API is healthy and initial inventory
is empty. The higher disk cap does not raise the three-container work limit.
Unrelated containers may be removed under the user's instruction; none is
observed in either expanded cohort. Unrelated images/volumes are not pruned.

Installed staged/dynamic-extension PHP transport, other runtime versions,
Windows PHP, TLS, multisite, alternate content layouts, an administrator named
`null`, and social addons remain unqualified. See [the deferred ledger](DEFERRED.md).
The prior User Registration publication has all ten workflows successful;
its exact-fork Ruby 3.4 job records 20,159 examples, zero failures and 33 pending.
Those CI/unit results add no Docker qualification and exclude this later fixture.

Read-only parent checkpoint: `/Users/dwelch/.codex/reports/pie-register-qualified-checkpoint-20261117`,
manifest SHA256 `a5081a9925977397e137b86b9fa13322615b7454948a0afe5cae84482143d00c`.
Its 13 entries reference 17 independently rehashed
seals containing 1890 exact entries, including every original
profile, the orphan-source investigation, baseline, native readiness, compatibility
regression and final replay. Full console/source/HTTP/database/resource/cleanup
evidence is retained separately from qualification counts.
