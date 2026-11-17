# King Addons registration and RCE verification, 2026-11-17

Qualified one owner in ten selected profiles with 36 passing public cases,
reaching **278 runtime owners in covered paths, 542 qualified profiles and
3,852 historical functional cases**. The broader campaign remains active.
No PR is created.

Owner: `exploit/multi/http/wp_king_addons_privilege_escalation`.
The credential repair is `1eca9a2fbfe`; owner SHA256 is
`f23f6ca364380ca5f1d8f1d2804f4f0a0a526dadda96519bb716391356ee95dc`.
The nine preserved profiles use fixture `23c9092b5aa`; the corrected root replay
uses `3066fd30e18829793c7bd36a75c415f1db8f1c6a`.

## Reproduction and independent target readiness

Use the [target guide](king_addons/README.md) for the default six-case command
and optional serial profile names. Official complete King Addons archives
24.12.92, 51.1.14 and 51.1.35 and Elementor 3.21.0 have pinned digests and full
file catalogs. The shared runtime is WordPress 6.8.3, PHP 8.3.28 and MariaDB
11.2.2, with a separate ordinary-role Postgres reporting database.

The Wordfence CNA record and [primary disclosure](https://www.wordfence.com/blog/2025/12/attackers-actively-exploiting-critical-vulnerability-in-king-addons-for-elementor-plugin/)
are checked against vendor source. Official SVN bytes for the later tags match
the downloads. The first affected tag is unavailable from SVN, while its official
ZIP and version labels are available and pinned. The official 51.1.35 distribution
internally identifies itself as 51.1.32 in both PHP header and constant; its readme
identifies 51.1.35. These labels and all vendor security checks remain intact.

A genuine Elementor canvas page renders the King Addons Login Register Form
widget, including its native column-width setting. Its localized nonce matches
the hidden registration nonce when registration is enabled. WordPress supplies
the actual plain-permalink query URL. Native gates independently validate real
passwords/cookies, roles, original-administrator upload, benign PHP/shell UID-33
execution and exact callback token/ACK before and after module calls. Disabled
registration retains the genuine localized nonce but omits the registration form;
its native handler rejects creation. Pre-seeded existing users undergo real
password, cookie and access checks.

The three earlier successful native-only profiles record 63 HTTP controls and
24 zero-resource snapshots; they add no Framework qualification. Five excluded
native setup attempts are sealed separately before any module call. Their setup
failures are not attributed to the production owner.

## Confirmed owner defect and repair

The unchanged-owner five-case baseline opens four genuine typed sessions and
passes both independent native gates, UID-33 execution, administrator/password
access, FileDropper restoration and teardown. Four reporting assertions fail:
credential cores are absent despite real vulnerability rows. Reporting queries
start at credential cores with left joins, so an absent login join cannot explain
the empty result.

The same five-case replay passes after the owner repair. Exactly one of 94 frozen
runtime inputs differs: the production owner. It now preserves a newly created
service-origin credential core after registration acknowledgement, before login.
Only successful WordPress authentication records a Successful login with a Time
attempt timestamp. Existing-account candidates are not persisted until their
supplied password authenticates. Reporting precedes payload upload and does not
infer administrator access. Inactive-database operation tolerates a nil core.
Passing Untried creation data does not itself create an Untried Login row.

Focused owner examples go from 15 examples/13 failures before to 15/0 after.
Their HTTP, authentication, payload and persistence interfaces are doubles; real
persistence is established by the public runs. A parent default-helper run passes
22 examples: 15 owner contracts and seven shared formatting examples, with zero
pending or outside errors. Changed Ruby passes syntax/RuboCop; owner msftidy,
module-guide tidy, PHP syntax and all resolved Compose preflights pass.

## Selected passing public profiles

| Profile | Release | Cases | Typed sessions | Credential/login pairs | Native HTTP | RSpec seconds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| king_addons | 51.1.14 | 6 | 5 | 3 | 55 | 219.7 |
| king_addons_minimum | 24.12.92 | 3 | 2 | 2 | 46 | 110.7 |
| king_addons_subdirectory | 51.1.14 | 5 | 4 | 2 | 52 | 159.1 |
| king_addons_plain | 51.1.14 | 5 | 4 | 2 | 52 | 159.8 |
| king_addons_fixed | 51.1.35 | 3 | 0 | 1 | 38 | 77.5 |
| king_addons_missing_nonce | 51.1.14 | 5 | 0 | 0 | 44 | 84.3 |
| king_addons_registration_disabled | 51.1.14 | 2 | 0 | 0 | 26 | 56.8 |
| king_addons_existing_admin | 51.1.14 | 3 | 2 | 2 | 52 | 119.0 |
| king_addons_existing_wrong_password | 51.1.14 | 2 | 0 | 0 | 46 | 104.9 |
| king_addons_existing_subscriber | 51.1.14 | 2 | 0 | 1 | 48 | 93.6 |

All selected cases have zero failures, pending or outside errors, and successful
teardown. Seventeen real sessions comprise eight Linux PHP Meterpreter sessions
with explicit embedded stdapi and nine Unix command shells. Every session performs
an independently verified UID-33 file operation. Repeat cases retain the selected
console module while actual run objects differ, preserve credential/core/login/
service IDs, and restore owned state. Actual cached encoded PHP bytes are captured
without regeneration eight times. An independent uploaded-ZIP capture is not
claimed.

The thirteen scoped credential/login pairs include genuine fixed-release and
existing Subscribers: their passwords authenticate but plugin upload is denied,
with no inferred administrator access. Incorrect existing passwords and disabled
registration save no credential. Missing-nonce 404 and ordinary 200 paths refuse
execution. No loot rows or files are expected. The 23 recorded workspace findings
include passive check/AutoCheck results; they are not 23 exploitation proofs.
In particular, disabled registration still receives a version/nonce Appears
check and finding while actual execution correctly refuses account creation.

## Preserved fixture failure and targeted replay

The original ten-profile aggregate exits **1**: nine profiles pass, and root has
six examples/one failure. The AutoCheck-disabled path opens a genuine fifth
session, saves its credential and restores selected state, but the fixture
incorrectly expects no vulnerability row. Framework session persistence records
proven exploitation independently of AutoCheck; the captured finding and unchanged
DB session reporter establish the cause.

All ten terminal profiles are sealed before the assertion changes. The fixture
now requires an anchored session-created finding on that path, while the forced
fixed/zero-session control retains its empty-finding requirement. The targeted
six-case root replay exits **0**. The owner remains unchanged by this correction.
There is **no single all-green 36-case aggregate**: the selected evidence combines
nine preserved passing profiles with the passing root replay.

All 92 unique tracked root inputs rehash from its exact Git revision; all 108
unique tracked inputs across the other nine rehash from their recorded revision.
Four ignored official ZIPs are separately pinned. The only current executable-test
delta for those nine is the reviewed root-specific assertion repair: their public
options all have AutoCheck true, so the existing true/default-true reporting
expectations remain identical. Their negative helpers are unchanged. Later target
README publication wording does not change executable inputs.

## State, resources and remaining limits

Selected original users/hashes/roles/tokens/usermeta, plugin options including
Elementor logs, pages/Elementor metadata, configuration and the complete plugin
tree restore. Existing fixture accounts are retained. Session cleanup requires
bounded count/age and the exact case User-Agent. Other WordPress options, security
rate-limit transients, service logs, auto-increment and free-space values are
excluded; complete database restoration is not claimed. No session/job remains.

The selected profiles contain 459 native HTTP controls and 120 cgroup snapshots
with no OOM or PID-limit event. Only one stack and at most three capped work
containers run, with matching memory/swap caps, CPU/PID limits, init and loopback
ports. All 50 attached volumes/networks are individually absent after teardown.
Both local Docker contexts expose the same empty engine. The restarted engine's
configured cap is about 1 TiB. Four unrelated connector containers observed around
the earlier baseline/replay are removed under the user's instruction; neither the
ten-profile cohort nor final root replay observes foreign containers. No unrelated
image or volume prune occurs.

Windows, other plugin/core/PHP/Elementor combinations, TLS, multisite, paid features,
alternate content layouts and staged/dynamic-extension PHP transport remain
unqualified. Explicit inline Meterpreter/stdapi and cmd/unix/reverse_bash success
does not qualify defaults or those transports. The owner retains created accounts;
lab-owned cleanup is explicit. See [the deferred ledger](DEFERRED.md).

The preceding Pie publication finishes nine successful workflows and one failed
Meterpreter workflow. Its Ruby 3.4 unit job actually executes fork f3ac1faf2c6 and
passes 20,159 examples with 33 pending. The failed native Mettle job instead checks
out upstream Framework e238eceec3fa4b9aa7b6996334a0acb64f5a261a because its commit
input is blank. Its reverse-HTTP file-operation timeout remains unverified and
does not validate this fork revision. Logs, TLVs and native debug output are sealed;
no retry or cancellation is dispatched. These CI results add no local coverage.

Read-only parent checkpoint: `/Users/dwelch/.codex/reports/king-addons-qualified-checkpoint-20261117`, manifest SHA256
`f14f17c42a80bd7e1e97e3cc4fbe8b87a21ea57d26214c28f4f3048875b5a4a4`. Its 55 entries reference
24 independently rehashed seals containing 2473 entries, including original
owner/harness failures, native readiness, focused contracts, final paths and prior
CI provenance. Final publication binds the committed report separately.
