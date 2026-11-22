# CouchDB Erlang node-name qualification

Two genuine DNS-named peers exposed a module defect: challenge acceptance
required the byte sequence for one fixed node-name length. Independent vendor
RPC and exact-byte controls passed on both peers, while each owning profile
failed both cases. With only the owner changed, both frozen profiles pass.
The full five-profile replay passes **13 examples, zero failures/pending/outside
errors**, and uses/closes twelve real sessions.

| Node | Challenge body bytes | Original cases/failures | Candidate cases/failures |
| --- | ---: | ---: | ---: |
| `couchdb@couchdb.example.test` | 39 | 2/2 | 2/0 |
| `couchdb@db.test` | 26 | 2/2 | 2/0 |
| `couchdb@127.0.0.1` | 28 | Previously qualified | Existing 9 cases replay successfully |

## Native prerequisites and failure separation

The [long-name](couchdb_erlang_named/README.md) and
[short-name](couchdb_erlang_shortname/README.md) profiles vary only supported
`NODENAME`/hostname configuration from the pinned official CouchDB 3.2.1/OTP23
target. The historical `monster` cookie is explicitly configured through the
stock entrypoint; the image's own normal default is not assumed vulnerable.

Before owning execution, bundled vendor Erlang proves the actual configured
node and OTP identity, correct-cookie RPC and wrong-cookie refusal. It writes
exact quoted Unicode/CRLF bytes twice as UID 5984, verifies them independently
and removes them. Native EPMD supplies the advertised distribution port.

Separate bundled `gen_tcp` diagnostics capture actual legacy status/challenge
frames and close their unauthenticated sockets. The frames identify the real
configured peer and contain 26/39-byte bodies, with no fixed 28-byte marker. The
raw captures and digests are retained, and committed unit fixtures match them.
These diagnostics do not replace the successful authenticated vendor controls.

The original owning check reports an unsuccessful connection/Safe result;
AutoCheck consequently prevents the command case. Both original runs retain
two failures with native controls passed, unchanged inputs and completed cleanup.
Each candidate run uses identical declared inputs except the owning source.
It reports authenticated check success and writes the benign command marker
twice as the real service user. These are module failures and repairs, rather
than failed target setup being counted as successful validation.

## Repair and regression coverage

The narrow repair validates the available fixed fields before indexing, the
actual 16-bit length, legacy `n` tag and version 5. It preserves the nonce offset,
cookie digest, successful return shape and command paths. Capture-derived tests
also cover truncated headers/bodies, wrong tag/version with the former marker
embedded in the nonce, trailing bytes and a missing challenge.

The frozen unit file changes **20 examples / 9 failures to 20/0**, including seven
shared framework examples. Combined handshake/Unicode specs pass **40/0** in
both the child and integrated parent. Syntax passes. RuboCop retains the same
six owner offenses with zero new offenses; the changed spec/native probe are
clean. Baseline and candidate module tidy both exit 2 for those inherited warnings.
Module-document tidy passes and existing human Scenarios remain byte-identical.

The final serial replay also refreshes the original check/command profile,
the five-case explicit OpenSSL/x86/x64/Unicode profile and the two-case untouched
initial-default profile. The twelve sessions correlate actual owner/payload,
UID 5984, PID, kernel birth, exact file bytes, a fresh public response, shutdown
and physical session-PID absence. Jobs, session registrations and temporary-file
sets are restored; service HTTP identity remains healthy. Full process ancestry,
relay children, sockets and database closure are not established by PID checks.

## Scope, evidence and resources

Final runtime: `20261122T065447-a3da40`. Original long/short runtimes:
`20261122T064727-62d7c8` and `20261122T065120-e38f50`. The original and candidate
receipts, native commands, raw captures, source hashes, source-unit capsule and
public-console logs remain retained separately. The native probe's optional
node parameter preserves the original default and validates its actual vm.args.

Four cases/two profiles are new; nine existing cases are replayed rather than
counted twice. The owner/native-probe inputs are explicitly refreshed. All other
720 prior inputs remain byte-identical, and six newly declared profile files bring
the retained set to **328 cases / 72 profiles / 728 current inputs**, with
**301 ordinary used/closed sessions** and 21 separate source variants.

Only one capped target/Framework pair runs at a time; each stack and its anonymous
volume is removed before the next. The two unused initialization helpers from
the fix agent are removed promptly by exact ID. Both Docker contexts finish
globally empty, including stopped containers; all **30 new /1,111 recorded
resource identifiers** are absent, and no new global volume remains. No image/
cache pruning, daemon restart or unrelated-volume removal occurs. The earlier
unrecorded Erlang pilot volume ID remains excluded from exact-ID counts, with
its prior set-based absence proof retained.

Complete TCP frame accumulation, modern negotiation, acknowledgment digest
validation, fixed-release/cookie controls, PHP after target reselection and
Windows remain separate. Protocol references are the
[OTP23 specification](https://github.com/erlang/otp/blob/OTP-23.3/erts/doc/src/erl_dist_protocol.xml)
and [supported image settings](https://github.com/apache/couchdb-docker/blob/main/README.md).
The full valuable feasible-module goal remains active. No PR is created.

**Summary:** Repairs a native-proven variable node-name rejection.
**What looks good:** Frozen native comparisons, captured-frame units and session replay.
**Concerns:** Wider protocol and target paths remain unqualified.
**Suggestions:** Continue those variants and the complete source inventory.
