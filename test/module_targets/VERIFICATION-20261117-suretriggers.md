# SureTriggers authentication bypass verification, 2026-11-17

Qualified one owner in ten profiles with **41 passing public cases in one aggregate
with exit 0**, reaching **279 runtime owners in covered paths, 552 qualified
profiles and 3,893 historical functional cases**. The broader campaign remains
active. No PR is created.

Owner: `exploit/multi/http/wp_suretriggers_auth_bypass`. The targeted repair is
`54f260af3ffcd56d980a42c31b1b2a93143b8ffb`; its owner SHA256 is
`1d5ad02c711b3e0da36ef21ba71c76eb0c56503e06f940e63685bbfb7798e1ef`.
Focused contracts are `4ef3dde9ee3`. The reusable WordPress native-control extraction
is `950c819dc38`; its King Addons root/fixed regression passes nine cases, adding
no qualification counts.

## Reproduction and independent native readiness

See the [target guide](suretriggers/README.md) for preparation and individual
serial profile names. The default six-case profile uses explicit PHP
Meterpreter/embedded stdapi and Unix reverse-shell payloads. It does not qualify
Framework's automatic payload selection.

Four official complete SureTriggers archives, 1.0.78/.79/.82/.83, have pinned
SHA256 digests and full installed-file catalogs. Header, constant, readme and
registered vendor REST callbacks are verified. The environment is WordPress
6.8.3, PHP 8.3.28 and MariaDB 11.2.2, with an ordinary-role PostgreSQL reporting
database. The reporting schema starts empty; Framework creates and uses it.

The [Wordfence disclosure](https://www.wordfence.com/blog/2025/04/100000-wordpress-sites-affected-by-administrative-user-creation-vulnerability-in-suretriggers-wordpress-plugin/)
and [Patchstack disclosure](https://patchstack.com/articles/additional-critical-ottokit-formerly-suretriggers-vulnerability-patched/)
are checked against CNA records and official vendor/SVN bytes. Empty-bearer
CVE-2025-3102 affects the unconfigured 1.0.78 control and is denied by 1.0.79 or
an existing key. Key-reset CVE-2025-27007 remains usable through 1.0.82 and is
denied by 1.0.83. A passive version Appears on configured 1.0.78 is retained;
it does not prove that empty-bearer execution works.

Six earlier native-only profiles pass without Framework calls. Public native
gates independently prove actual REST permissions, malformed-user responses,
valid-key positive controls, passwords/cookies/administrator roles, normal plugin
upload and benign PHP/shell UID-33 execution before and after module cases.
Callback controls exchange exact tokens and ACKs. No vendor security check,
nonce, user record or SaaS response is fabricated. Authenticated SaaS positives
on the fixed release are not claimed.

## Confirmed owner defects and causal repair

The unchanged six-case baseline opens four genuine typed sessions and passes
native gates, UID-33 operations, real password/admin access, FileDropper restoration
and teardown. Four reporting assertions fail: authenticated credentials remain
Untried with no attempt timestamp. Login rows exist; this is not a missing-row
or inner-join artifact.

The fifth failure follows a real HTTP-200/outer-success response containing
`data.result.empty_user_login`. No account exists, yet the original owner prints
Admin created and stores a credential/login, credential loot and an account
finding before failing an unauthenticated upload.

The repaired owner validates a positive native WordPress user ID and administrator
role, requires a nonempty successful WordPress-login cookie, and only then records
an authenticated administrator, a Successful login with a Time attempt timestamp,
and the existing loot. It accepts a returned updated administrator without
claiming the account was necessarily new. Authenticated credentials remain valid
if later payload upload fails; inactive-database operation tolerates nil returns.

The corrected-fixture original six-case baseline is **6 examples/5 failures**;
the fixed replay is **6/0**. Exactly one of 94 frozen runtime inputs changes: the
production owner. Focused contracts go from 16 examples/12 failures to 16/0;
seven automatically loaded formatting examples also pass, making aggregates
23/12 and 23/0. HTTP/authentication/persistence/payload interfaces in those focused
contracts are doubles; real reporting and sessions are established below.

## Selected passing profiles

Actions below are CVE-2025-3102 and CVE-2025-27007.

| Profile | Plugin | Action | Cases | Typed sessions | Native HTTP | RSpec seconds |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| suretriggers | 1.0.82 | 27007 | 6 | 4 | 60 | 179.5 |
| suretriggers_empty | 1.0.78 | 3102 | 6 | 4 | 74 | 221.3 |
| suretriggers_empty_fixed | 1.0.79 | 3102 | 3 | 0 | 48 | 77.3 |
| suretriggers_configured | 1.0.78 | 27007 | 4 | 2 | 70 | 125.9 |
| suretriggers_empty_configured | 1.0.78 | 3102 | 3 | 0 | 64 | 89.0 |
| suretriggers_reset_boundary | 1.0.79 | 27007 | 4 | 2 | 54 | 110.5 |
| suretriggers_fixed | 1.0.83 | 27007 | 3 | 0 | 30 | 54.0 |
| suretriggers_plain | 1.0.82 | 27007 | 4 | 2 | 54 | 113.3 |
| suretriggers_subdirectory | 1.0.78 | 3102 | 4 | 2 | 68 | 128.3 |
| suretriggers_no_check | 1.0.82 | 27007 | 4 | 2 | 54 | 118.4 |

The single final aggregate has zero failures, pending cases or outside errors,
with all teardown checks passing. Eighteen real sessions comprise nine Linux PHP
Meterpreter sessions and nine Unix command shells. Every session performs a
native-verified UID-33 file operation; its actual exploit action is checked.
Nine actual cached encoded PHP payloads are captured without regeneration.
An independent uploaded-archive byte capture is not claimed.

Fourteen scoped credential/login pairs are Successful with bounded attempt times
and no inferred access level. Repeats retain the selected console module and
stable credential/core/login/service IDs while actual execution objects differ.
Eighteen exact credential loot files belong to successful authenticated cases;
rejected usernames and denied targets save no credentials or loot. The 43 distinct
reported findings include 15 in contexts with no session; they are not 43
exploitation proofs.

Actual target logs show the plain and subdirectory pretty POST endpoints returning
404, and real module output records the REST fallback branch. The `AutoCheck=false`
positive and denial calls explicitly print the disabled-check path without an
automatic-check invocation. Configuration alone is not used as branch proof.

## Preserved harness failures

All original evidence is retained before edits. An early negative matcher used
Exploit failed while genuine fail_with output says Exploit aborted due to failure;
the matcher is corrected before the strict source-only reproduction.

The first broader exploratory matrix mistakes the idle console action for the
per-run execution clone's action. It is deliberately stopped after preserving
completed passes and harness failures. The fixture retains the actual session
exploit-action assertion and restores an owned ledger call even if its callback
assertion fails. A second exploration proves four actual 3102 sessions and invalid
input rejection, but standalone check still uses the idle default action: the
console parser drops the separately parsed inline ACTION. Standalone check now
uses the documented public set ACTION workflow before checking. Its selected
module action and real check reason are verified. No production change hides
these fixture/setup errors, and their interrupted runs add no counts.

Raw interrupted CLI exits are -2 and preserved with clean teardown. Earlier
exports that labeled normalized shell status 130 as the raw exit are explicitly
superseded; corrected accepted exports bind to the actual controller receipt.
The intended contract of inline check ACTION remains a separate investigation.
The final unchanged-owner-after-repair ten-profile replay is the all-green
41-case result counted here.

## State, resources and limits

Ownership-checked lab cleanup restores selected users/password hashes/roles/tokens/
usermeta, plugin option bytes including original encrypted keys, pages, config
and complete plugin trees. Production retains created accounts and changed keys;
operator cleanup is explicit. Other WordPress options, logs, auto-increment and
free-space changes are excluded. Complete database restoration is not claimed.
No session or job remains in any selected profile.

The selected run records 576 native HTTP controls, 46 benign native execution
proofs, 20 exact callback successes and 120 cgroup snapshots without OOM or
PID-limit events. One stack and at most three capped work containers run, with
CPU/PID/init, matching memory/swap limits and loopback ports. All 50 attached
volumes/networks are individually absent after teardown. Background connector
containers are removed under the user's instruction; their brief presence raises
the observed global peak to four while the work peak stays three. No unrelated
image or volume prune occurs. Docker's restarted configured disk cap is about 1 TiB.

Windows, default/staged/dynamic PHP transport, existing-account collision/update
flows, authenticated fixed-release SaaS positives, other releases/runtimes, TLS,
multisite and alternative delivery families remain unqualified. Human module
Scenarios are unchanged. See [the deferred ledger](DEFERRED.md).

The preceding King Addons publication `1d2cc643b7b` finishes all ten CI workflows
successfully. A normal Ruby 3.4 unit job actually tests that fork commit with
20,174 examples / 0 failures / 33 pending. Inspected Mettle and Python 3.8 macOS jobs
instead check out upstream e238eceec3fa4b9aa7b6996334a0acb64f5a261a; their
51/0 and 91/0 results do not validate this fork revision. No retry/cancellation
or CI code change is dispatched. This adds no local qualification.

Read-only parent checkpoint: `/Users/dwelch/.codex/reports/suretriggers-qualified-checkpoint-20261117`,
manifest SHA256 `3d42471d8670aa4fb02ef5ab6ddd3db0e37f82a2b18468763cbe5db619bb3367`.
Its 114 entries reference 22 independently rehashed seals containing
2880 entries: causal originals/fix, native readiness, focused contracts, shared
helper regressions, corrected exploratory failures, selected profiles and prior
CI provenance. Publication binds the committed report separately.
