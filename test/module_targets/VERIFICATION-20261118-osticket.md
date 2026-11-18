# osTicket file collection diagnostics, 2026-11-18

Two repairs are verified, while complete file recovery remains **unqualified**.
Strict failing cases remain enabled. No owner/profile/case breadth increment is
claimed: the qualified campaign totals remain 295 owners, 598 profiles and 4,186
historical functional cases. No PR is created.

| Profile | Actual target | Cases / failures | Native controls | Verdict |
| --- | --- | --- | --- | --- |
| `osticket` | official 1.18.2, PHP 8.3.28, `/` | 6 / 2 | before/after pass | incomplete recovery/reporting |
| `osticket_prefix` | official 1.18.2, PHP 8.3.28, `/support` | 6 / 2 | before/after pass | incomplete recovery/reporting |
| `osticket_fixed` | official 1.18.3, PHP 8.3.28, `/` | 3 / 0 | before/after pass | both real PDF exports reject exfiltration |

All three results have zero pending cases and zero errors outside examples.
Run `20261118T134144-740290` is deliberately red overall: 15 cases, four failures.
The [target guide](osticket/README.md) includes pinned source preparation and the
namespaced guarded invocation. The runner's nonzero exit is an investigation
result; neither a working installer nor a success message proves module success.

## Independent setup gates

The genuine HTTP installer creates each fresh MariaDB database and staff account;
vendor APIs create a confirmed client and disposable tickets. Both portals reject
a wrong password, accept the correct account and expose its protected ticket.
Ordinary PDF exports contain the known ticket text. The pinned researcher PoC
injects a Base64 file canary into a separate fresh ticket. Poppler independently
recovers its exact encoded bytes from image pixels on 1.18.2; the same bytes are
absent from both portal exports on 1.18.3. These controls run before and after the
module cases, without importing the Framework decoder. Every shipped vendor PHP
file matches the release tree. Only the normal installer-generated configuration
is additional application PHP source.

The official [1.18.2 requirements](https://raw.githubusercontent.com/osTicket/osTicket/v1.18.2/README.md)
include PHP 8.3. Earlier 1.18.1/PHP 8.3 experiments remain exploratory evidence:
that release predates declared PHP 8.3 support. They do not qualify that pairing.
The final profiles use 1.18.2 and 1.18.3 on the same pinned PHP image. WordPress's
application and entrypoint are bypassed; its image supplies PHP/Apache extensions.
The [upstream PoC](https://github.com/horizon3ai/CVE-2026-22200/tree/06a50ca2b192ee91d1cc6cb60a3b4553392c2654)
is pinned and checksum-checked as a separate runtime input.

## Repairs and observed behavior

The decoder previously rejected an actual Base64 value because iconv filter bytes
followed its padded end. The old module saved 407 encoded/padding bytes for a
71-byte file and printed success. A private same-image comparison changes only
the owner and decoding helper among 11 inputs and saves the exact 71 bytes.
The caller now supplies the requested encoding. Explicit Base64 preserves small
and binary files, trailing NULs and bytes resembling the old padding sentinel;
plain mode does not guess that a Base64-looking file should be decoded. Omitted
encoding retains the helper's legacy behavior. Actual delivery can still truncate
files before decoding, as the strict cases below demonstrate.

Staff ticket lookup also crossed listing rows: it returned internal ID 1 for a
different requested ticket number and posted to the installer's sample ticket.
The repair associates each exact visible number with its own link. Bounded
fallback verifies the actual detail heading and linked internal ID, excluding
incidental mentions in ticket text. The explicit `TICKET_ID` override is retained.
Capture-derived identity contracts change 13/8 to 13/0; all 31 identity/decoder
contracts pass together. Scoped RuboCop and msftidy pass for both repairs.

On supported 1.18.2, both portals save the exact 71-byte native canary, repeat with
AutoCheck disabled and retain the same active console configuration. Client ticket
creation also succeeds. Ten canary reads across root/prefix save exact bytes.
Real `check`/`run` method traces and loaded-source hashes are retained. Each case
uses a fresh reporting workspace; fixture tickets are removed using vendor APIs.
The installer's original ticket and entry count remain unchanged after every case.
This selected recovery is performed by the harness; the module's ticket/reply
side effects remain part of its behavior.

## Remaining investigations

- A 49-byte ASCII file returns only ten bytes on both supported vulnerable
  profiles. The independent original PHP filter chain also truncates its encoded
  input. Investigate payload construction/stream flushing before changing the
  decoder or calling this a setup success. The exact-file assertion remains red.
- On the root profile, the genuine 6,402-byte configuration returns its first 6,364 bytes. The exact
  file assertion remains red. Plain and raw-Deflate modes also exhibited upstream
  payload truncation in exploratory controls; complete recovery, large files,
  empty files and binary delivery remain unqualified.
- The module prints the actual extracted database username/password but saves
  zero credential records in the current workspace. Its actual salt/email notes
  do persist in the same real Framework database. The extracted DB hostname is
  the private service name `db`; address resolution/reporting semantics require
  investigation. The cause is not established by the empty credential query.
- Automatic portal fallback, staff ticket creation, explicit IDs, additional
  authentication failures and other target/encoding variants remain unqualified.

The first public scaffold run also exposed harness defects: workspace counter
state was copied per example, and the after-control reused a PDF scratch directory.
The final run uses metadata-derived workspace names and phase-specific scratch
paths. Python bytecode writes are disabled so a fresh checkout does not acquire
new runtime inputs mid-run. Those earlier failures are preserved separately.
Earlier narrative notes miscounted the canary/short file as 67/47 bytes; raw data
and all comparisons used the actual 71/49 bytes. The correction is retained.

## Resources and evidence

At most three task-namespaced containers run at once, one serial stack: app and
MariaDB each 512 MiB, reporting PostgreSQL 384 MiB, with CPU/PID caps. All 36
memory/PID event captures contain zero events. Inspection verifies task namespace
labels. Independent post-run checks confirm all 24 recorded containers, networks
and volumes are absent. The namespace has zero remaining containers; no unrelated
container is stopped or removed.

Immutable capsule `osticket-functional-20261118T134144-740290` contains 643 files,
45 unchanged declared inputs, complete captures, actual loot, reporting queries,
source snapshots and the independent ownership/resource audit. Its SHA256 manifest
is `9c946329c1d73bb9e136975483c1b23c49aff22f1e50ad7d8a6b79c96fa48de3`.
The 48-file focused-contract capsule manifest is
`2081fea60171eca413beb7a5973a38b468d832d3fde22af6d9082a369bb168bb`.
The source-only decoder replay capsule manifest is
`035bf96a5d158c2ebc28ff990d13a068dd4c1f86afdf922f837550def1869828`.
Final root checks pass both focused spec files separately (18/0 and 13/0),
RuboCop across six changed Ruby files and msftidy. Module-document tidy reports
21 existing warnings, identical to the original document; there are no new
warnings. The static inventory has 5,179 source files, 4,299 pending selectable
candidates, 224 pending documented container hints and zero stale reviews.
Results/documentation are updated after sealing; runtime source is unchanged.
Human-authored module Scenarios are preserved.

**Summary:** Native container diagnostics expose two repaired defects and retain
strict unresolved cases. **What looks good:** exact canary recovery, both portals,
repeats, ticket identity, patched rejection, independent gates and owned teardown
are verified. **Concerns:** complete file recovery and credential persistence are
not qualified. **Suggestions:** investigate those two contracts before expanding
encoding/authentication coverage or counting the affected profiles as qualified.
