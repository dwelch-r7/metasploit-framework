# Secure Copy SQLi qualification, 2026-11-16

This checkpoint adds **one runtime owner, eight profiles and twenty functional
cases**, reaching **270 runtime owners in covered paths, 476 profiles and 3,663
historical functional cases**. The [reusable profiles](secure_copy/README.md)
exercise the existing Secure Copy Content Protection SQLi module through genuine
public `check` and `run` calls. Earlier coverage remains historical and the broader
campaign remains incomplete. No PR is created.

## Genuine sources and prerequisites

Unmodified official WordPress plugin ZIPs are pinned by complete archive and
all 81 installed-file hashes per release:

| Release | Native result | Archive SHA256 |
| --- | --- | --- |
| [2.8.1](https://downloads.wordpress.org/plugin/secure-copy-content-protection.2.8.1.zip) | Full data and timing controls succeed | `ae422a932d78603e5c01f229ba42010644bb8f1ef0adc219f571a8060525b58c` |
| [2.8.2](https://downloads.wordpress.org/plugin/secure-copy-content-protection.2.8.2.zip) | Same probes refuse extraction | `ae7fb4579808117348c8dc75894dc1757900866da19f540b6c1b9cfd89aefd41` |

The stack uses pinned WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2, plus a
fresh ordinary-role PostgreSQL 16 reporting schema and an isolated host console.
Normal plugin activation creates its five vendor tables and default subscription
before exiting through its redirect hook. A second PHP process verifies activation
and adds the native subscription shortcode through the WordPress post API.
The populated profile submits that actual public form once before its baseline.
Mail delivery and optional remote-stream geolocation are disabled by owned lab
configuration; vendor source is unchanged. External integrations are unqualified.

Independent native controls recover a marker and a complete genuine user hash
only on affected source. True/false timing controls also distinguish empty and
populated reports, including matching and nonmatching report IDs. The standalone
qualified controls make 36 HTTP requests and no module calls. Public profiles
repeat data and timing gates before and after module execution.

Two earlier native failures are retained as setup/control defects. The first
manifest used lowercase `readme.txt` where the archive has uppercase `README.txt`;
Linux rejected that path despite the case-insensitive host accepting it. The
initial independent UNION control also left the vendor's trailing `vote_date`
predicate out of scope. The corrected control exposes that column and balances
the vendor's appended parenthesis. Neither failed probe invokes a module or adds
coverage. Both clean up completely.

## Confirmed owner defect and repair

Original public custom-prefix run `20261116T205350-3d3203` passes its passive
check, then the run prints an empty table and persists no credentials. Independent
native controls succeed. Actual target logs report two queries against nonexistent
`wp_root.wp_users`, while the genuine site's prefix is `wp_native_`.

The repair reuses the existing database-scoped WordPress SQLi prefix identifier
and applies the returned table name to extraction and display. Missing discovery
results stop with an explicit failure. It preserves options and credential/service
metadata. Separate-worktree candidate `6470f0b5eda0ff02847c75b12e242851d133f3fd`
is imported as `a0f0e6f115cdc3c5c322beb0bcd0e428a9cf12ad`; all three blobs match.
The same final twelve unit examples have seven original failures and zero repaired
failures. SQL transport, Framework, UI and reporting are explicit unit doubles;
user values come from a captured native synthetic lab. Parent default invocation
passes nineteen examples: twelve owner cases and seven autoloaded support cases.

Repaired public run `20261116T210820-01e44e` uses the same declared inputs with
only the owner changed. Both cases pass; the complete native 63-byte hash and
correct credential/service/module origin persist. This establishes the concrete
prefix defect separately from either native setup/control failure.

## Final public matrix

Every final profile has zero failures, pending cases and outside errors.

| Profile | Cases | Accepted run | Result |
| --- | ---: | --- | --- |
| [secure_copy](secure_copy/README.md) | 5 | `20261116T212053-51da35` | Passive check, two complete extractions with stable reporting IDs, closed check/run |
| [secure_copy_subdirectory](secure_copy_subdirectory/README.md) | 2 | `20261116T213025-7edbc9` | Actual /wordpress install and complete hash |
| [secure_copy_prefix](secure_copy_prefix/README.md) | 2 | `20261116T210820-01e44e` | Actual wp_native_ tables and complete hash |
| [secure_copy_populated](secure_copy_populated/README.md) | 2 | `20261116T213544-afc691` | Native form creates a report; complete hash persists |
| [secure_copy_count2](secure_copy_count2/README.md) | 2 | `20261116T214116-804a07` | Two complete native credentials persist |
| [secure_copy_fixed](secure_copy_fixed/README.md) | 3 | `20261116T211631-630f01` | Safe check, normal refusal and AutoCheck-disabled refusal |
| [secure_copy_inactive](secure_copy_inactive/README.md) | 2 | `20261116T211748-16bd31` | Passive version detection, SQL extraction refusal |
| [secure_copy_absent](secure_copy_absent/README.md) | 2 | `20261116T211902-a32859` | Unknown check and run refusal |

These are nine public checks and eleven public runs: six positive extraction
calls and five refusal runs. Six distinct complete password-hash credentials
persist across the positive profiles, with correct native values, WordPress
service, endpoint, type and module origin. Repetition preserves credential and
service IDs. No HTTP, SQL, target-protocol or credential-reporting doubles are
used in the functional cases. Jobs and sessions finish empty, with no loot.

Six deduplicated passive vulnerability metadata rows also exist, including the
inactive-plugin profile. Passive version detection alone does not establish
working SQL injection or successful extraction. The separate extraction assertions
and independent native gates establish those positive results.

All source, users and five vendor-table snapshots remain identical before/after
module calls. Final controls make 98 native HTTP requests; those are additional
target-validation requests, not extra functional cases. Positive runs request
one user and use `SqliDelay=0.6`, except the explicit two-user profile. Bounded
longer timeouts allow complete blind extraction without accepting truncated data.

## Verification, cleanup and limits

All **75 consumed paths** match the final evidence: **73 tracked blobs** are
exact in source/fixture commit `f3f09d7696b71ccee820068eabf88e8d1ed440d5`, and two ignored official ZIPs match
their catalog hashes. Runtime records retain their actual earlier revision and
working-input hashes. The full human module guide and Scenarios are unchanged:
SHA256 `35e90c635e8fd73df648b6f48a2ceeecbdaa396b623f2f27402aad0c303916d7`.

New functional, unit and preparation Ruby files have zero RuboCop offenses.
One pre-existing owner `Lint/RedundantPeerInPrint` warning remains unchanged.
Full msftidy exits 2 before and after repair solely because it invokes that lint;
direct metadata checks pass. This is recorded as a baseline limitation, not a
clean full-msftidy result.

Complete modern WordPress `$wp$2y$` hashes are stored unchanged, but their
`jtr_format` is null. The existing classifier has no dedicated `$wp$` branch;
automatic cracking-format selection is a separate library follow-up. No raw hash
loss is observed. Other plugin releases, runtime/database combinations and
external integration behavior remain unqualified.

Each profile runs serially with three capped containers: app 1 CPU / 512 MiB,
MariaDB 0.5 CPU / 512 MiB and PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory,
PIDs are limited to 128, init is enabled and published ports bind loopback.
All 96 cgroup snapshots show zero OOM/PID-limit events. All forty attached volumes
and networks are independently absent; project and global container inventories
are empty, the advisory lock is free and no campaign Ruby process remains.
No unrelated image or volume is pruned. The last batch finishes successfully
without an observed interruption. No new Docker workload starts after the
user announces the restart.

All 675 final runtime entries are independently rehashed. The **38-entry**
qualified checkpoint seal references sixteen exact seals with **1,058
independently rehashed entries**, covering native successes/setup failures,
the original public failure, the separate fix, all final profiles and earlier
publication CI follow-ups. It is stored at
`/Users/dwelch/.codex/reports/secure-copy-qualified-checkpoint-20261116`, manifest
SHA256 `9620367daba67780cd6c165d3e5ada5ce59e2e39636156b20de2e94961106e71`.
Fresh static inventory has 5,179 sources, 4,622 candidates, 271 registered
candidates, 4,325 pending candidates and 235 pending documented container hints.
All 29 source-pinned reviews are current. Registration is not proof of runtime
qualification.

**Summary:** The covered public SQLi gathering/reporting paths pass after a
narrow table-prefix repair. **What looks good:** Genuine sources, complete values,
repeat persistence, paths, prefixes, table states, negative cases and teardown
are verified. **Concerns:** No material issue remains in the covered owner repair;
the existing hash-format classifier and baseline lint warning remain explicit
follow-ups. **Suggestions:** Qualify automatic cracker-format selection separately
before claiming support for these modern WordPress hashes.
