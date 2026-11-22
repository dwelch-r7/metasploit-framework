# CouchDB initial payload defaults and target reselection

The initial Unix target/payload default now has native proof: two owner OpenSSL
sessions execute without setting TARGET or PAYLOAD. A separate configuration
case confirms the effect of explicitly reselecting target0. The serial run
passes **7/0/0**, with zero errors outside examples and twelve used/closed
sessions. No production source changes are needed.

| Profile | Cases | Used/closed sessions | Purpose |
| --- | ---: | ---: | --- |
| [couchdb_erlang_sessions](couchdb_erlang_sessions/README.md) | 5 | 9 | Replay existing session/command paths after correcting documentation |
| [couchdb_erlang_default](couchdb_erlang_default/README.md) | 2 | 3 | Initial defaults and explicit same-target reselection |

## Correction to the previous interpretation

The previous checkpoint described a PHP selection as the fresh console's
initial default. That description was incorrect. The original raw log shows:

1. `use exploit/multi/http/apache_couchdb_erlang_rce` selects OpenSSL.
2. The fixture then issues `set TARGET 0`.
3. The console reports a switch from OpenSSL to PHP.

A read-only module-loading probe independently returns target0/OpenSSL as an
imported default, including after explicit default reimports. The console's
`cmd_set` implementation invokes automatic payload selection when TARGET is
set, even if its index is unchanged. The PHP observation followed that command.
It did not demonstrate a constructor/datastore defect or an initial-default
owner failure.

The earlier wrong expectation and all its native/session proofs remain retained.
The earlier source capability/Unicode defects and frozen source comparisons
remain valid; this follow-up corrects the interpretation of a different fixture
failure.

## Native execution and configuration proof

The new profile reuses genuine pinned CouchDB3.2.1/OTP23 with the explicit
historical cookie, normal stock handlers and vendor RPC. Native HTTP/runtime,
cookie and UID-owned command controls precede owning execution. Its initial
stock OpenSSL handler session is exercised and shut down independently.

Before each owning call, the public console reports target0, the imported
`cmd/unix/reverse_openssl` default and the actual module method source. Both
execution command lines omit TARGET and PAYLOAD, rather than setting those
fields to presumed defaults. Both actual callbacks identify the owning module
and OpenSSL payload family.

The separate reselection case records target0/OpenSSL with default lookup before
`set TARGET 0`, then target0/PHP with an explicit lookup afterward. Live native
checks confirm PHP is absent. It verifies that configuration transition and does
not execute the reselected PHP family. This remaining prerequisite is distinct
from the now-qualified untouched initial default.

All twelve sessions correlate actual owner/payload, UID5984, PID, kernel birth,
exact proof-file bytes, a fresh public response and shutdown. Native checks prove
session-PID disappearance; Framework registrations, jobs and temporary-file sets
are restored, and CouchDB HTTP identity remains healthy. Whole process ancestry,
relay-child/socket/database closure and PHP execution are not claimed.

## Verification and resources

The earlier five-case profile passes again with its executable inputs unchanged.
Its corrected README is the sole changed input among the previous717; all
other716 remain byte-identical. Five newly declared inputs bring the retained
set to **324 cases /70 profiles /722 byte-verified declared inputs**, with
**289 ordinary used/closed sessions** and21 separate source variants. The twelve
new sessions comprise nine from the replay and three from the initial-default
profile; replayed cases are not counted as new coverage.

New Ruby syntax/lint and the two-example dry run pass. Module-document tidy and
human-Scenario preservation are checked. Production Ruby, protocol and payload
sources are unchanged, so this follow-up does not repeat unrelated unit suites.

The first launcher attempt timed out on read-only Docker inventory before any
guard, observer, module call or container started. It has no module verdict.
After both contexts returned healthy empty inventories, a fresh invocation ran
the profiles serially. The final runtime is `20261122T062226-885451`; functional
RSpec times, including controls/startup, are174.38s and78.30s.

Only one capped target/Framework pair runs at a time; each complete namespaced
project and anonymous volume is removed before the next. Both contexts finish
globally empty, including stopped containers. All **8 new /1,081 recorded Docker
resource IDs** are absent; no new global volume remains. No helpers, image/cache
pruning, daemon restart or unrelated-volume removal are involved. The prior
Erlang pilot's unrecorded volume ID remains excluded from exact-ID counts, with
its earlier set-based absence proof retained.

The contribution guide now distinguishes initial defaults from target-triggered
reselection. PHP execution, Windows, fixed-release/cookie controls, node-name and
stream/reply variants remain separate work. The complete valuable feasible-
module goal remains active. No PR is created.

**Summary:** Qualifies the real initial default and corrects a fixture interpretation.
**What looks good:** Public console transitions, native controls and physical closure.
**Concerns:** Reselected PHP and wider paths remain unqualified.
**Suggestions:** Continue native variants and the complete source inventory.
