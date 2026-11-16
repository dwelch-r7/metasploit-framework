# Depicter native calibration, 16 November 2026

Status: all seven current-input profiles pass. This checkpoint adds one owner,
seven profiles and 31 cases, reaching **261 runtime owners in covered paths,
414 profiles and 3,458 functional cases**. Earlier campaign scope remains
historical; this is not a whole-campaign replay against the current harness.

## Genuine application prerequisite

Official WordPress plugin ZIPs were downloaded and checked before installation:

| Release | ZIP SHA-256 | Runtime |
|---|---|---|
| 3.6.1 | `273803d649486194e0a0e3c6c09daa4191228dc357fbaabe7d0d70c5db96d208` | WordPress 6.8.3 / PHP 8.3.28 |
| 3.6.2 | `e3a474aaa26911a596e2c8dbd01d48408d9641edaf90b26901e33f36feb9e944` | WordPress 6.8.3 / PHP 8.3.28 |

The [Wordfence disclosure](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/depicter/slider-popup-builder-by-depicter-361-unauthenticated-sql-injection-via-s-parameter)
identifies CVE-2025-2011 as affecting releases through 3.6.1 and fixed in 3.6.2.
Both tested packages require a modern runtime; 3.6.1's plugin header requires
PHP 7.4 and WordPress 5.3. The old PHP 7.3 lab was therefore not used.

The disposable app activates the unmodified plugin through WordPress, which
creates the genuine tables. Its repository creates and renames a document, and
a public HTTP form submission with a genuine guest nonce creates a lead and two
fields. Normal search retrieves the submitted UTF-8 field content; a search
without a matching lead returns an empty result.

Independent HTTP requests to 3.6.1 retrieve the native database name through the
five-column UNION used by the module. Both page 1 and page 2 succeed. Captured
MariaDB general-log queries show the ORM selecting the five-column lead table
and the SQL comment excluding the trailing LIMIT/OFFSET; the apparent seven
selected fields in an earlier builder stage do not invalidate the exploit.
Seven-column requests return no result. These observations rule out the initial
column-count and pagination hypotheses on this exact release/runtime.

On 3.6.2, public normal and injected lead-index requests return HTTP 401. An
actual administrator HTTP login followed by the dashboard's genuine CSRF token
permits normal searches; the same authenticated injection yields no hits.
The release source adds dashboard-CSRF middleware to the index/list routes and
also sanitizes the search argument. Public form submission still works.

## Calibration failures and evidence

Three prerequisite attempts failed before any module call. The first supplied a
text content ID to an integer plugin field; the fixture now supplies numeric ID
101. Two patched-release attempts omitted the administrator/CSRF prerequisite
for normal lead listing. They are preserved as fixture corrections, not module
defects. No vendor source or route was patched to make a target respond.

| Immutable local evidence archive | Result | Entries | Manifest SHA-256 |
|---|---|---:|---|
| `depicter-native-3.6.1-20261116T070829-seal` | Fixture content-ID mismatch | 62 | `2516779bf27e41c5e83fcbebac6feef79700e70a5b1b2b6b4de82a8f44a4d837` |
| `depicter-native-3.6.1-20261116T070917-seal` | Native passed; zero module calls | 72 | `220c9da26446e91774817f8d461d4338ae89174bbc5c3c21de6174693408ab98` |
| `depicter-native-3.6.2-20261116T070952-seal` | Missing authenticated normal-listing control | 62 | `d0e252226dbbbb810b10a16a8865871b09f87a0a6e0e451274c1ae0abe5a472e` |
| `depicter-native-3.6.2-20261116T071046-seal` | Missing dashboard CSRF token | 62 | `66b09e7ff4252817bf4b4b177f42c03d82f1c14ac0d8ca4f5d25716d9797eb31` |
| `depicter-native-3.6.2-20261116T071137-seal` | Native passed; zero module calls | 72 | `45da32c998d0e0a9c05e59e2f167ff5a29016f2bb31c47f7b1366698c134aa9a` |

Archives are under the operator's local `.codex/reports` directory and contain
raw requests, responses, source/input hashes, native database snapshots, command
exits, counters and cleanup checks. They are not published fixture substitutes.
Each completed attempt removed its exact project's containers, networks and
volumes and verified the global container inventory empty. Passing attempts used
two containers, 0.5 CPU / 384 MiB app and 0.5 CPU / 512 MiB database, with equal
memory/swap, 128 PIDs and init. Before/after counters recorded no OOM or PID-limit
events. Source hashes, native users and lead data remained unchanged after the
read-only SQL probes.

The module source and human guide/Scenarios remain unchanged at this stage.
Other releases, platforms and runtime combinations have not been qualified.

## Original module functional reproduction

The unchanged module (`c8b481513d7b1d09b52b68059ef67a0206c3a0e6c45ac58025b5a2776ffe773f`)
was exercised through public console check/run calls with real PostgreSQL
reporting. A first root attempt hit a test matcher typo (`start_with?` instead
of the RSpec `start_with` matcher), after credential comparison and persistence.
Its four affected extraction examples are fixture failures, not module defects;
that attempt is preserved before correction. Corrected strict lint, syntax,
seven resolved Compose configurations and all 31 collected cases pass preflight.

The corrected original-source serial run `20261116T072332-e92821` completed:

| Profile | Cases / failures | Public calls | Independent HTTP requests |
|---|---:|---:|---:|
| Root | 7 / 2 | 12 | 17 |
| Subdirectory | 5 / 5 | 5 | 17 |
| SQL aggregation limit 96 | 5 / 3 | 7 | 17 |
| Patched 3.6.2 | 3 / 2 | 4 | 17 |

All four native prerequisites and before/after controls pass. There are zero
pending examples or outside errors. Every project completes cleanup and all
before/after memory/PID counters show no OOM or PID-limit event. These failed
module suites do not add campaign qualification counts.

Confirmed module defects:

- The AJAX URI ignores `TARGETURI`. Root checks even report Vulnerable when
  configured with a nonexistent installation path. A genuine `/wordpress/`
  deployment passes native extraction but fails every module case.
- The callback returns an error string, but the caller compares the SQLi object
  with that string. A real PostgreSQL endpoint and the patched plugin's HTTP 401
  are labeled Safe. With AutoCheck disabled, the error text becomes a table
  prefix and collection raises `Rex::RuntimeError: Invalid number of columns!`.
- `COUNT` is documented and consumed but unregistered. Changing it produces an
  unknown-datastore-option warning, although root extraction honors the value.
- A real MariaDB `group_concat_max_len=96` silently truncates collection. Native
  per-user queries retrieve all four complete hashes. The original module saves
  two users and persists a five-byte hash fragment for `module_author`, whose
  native hash contains 63 bytes. Default COUNT=1 remains intact; complete and
  COUNT=2 collections fail exact-value comparison.

On an ordinary root database, all five positive cases now pass: repeated checks,
default COUNT=1, complete extraction, COUNT=2 with AutoCheck disabled and complete
extraction with AutoCheck disabled. Every extraction is repeated and compared
against complete native hashes, persisted credentials and exact loot contents.
The shared WordPress SQLi helper and module guide remain untouched. The
module-local repair and final qualification are documented below.

The immutable root/prefix/low-limit/fixed evidence archives contain respectively
221/224/224/224 entries. Their manifest SHA-256 values are respectively
`3bfaccf462f6621f629eceee16e0cc0e2963fdb7f75871660d0fa3644fa9422c`,
`f6d577e144ca34ae7af66f3d5594db39f8c0d7a7ff5c1f1c950043fb83770716`,
`6ad1484f7d9c6d11da660639c0556a75592ddf89a04f302be5805b6448adf5f2`, and
`6304f02aeb67350d78ff8cd48a642bf83b48abfae1f77a806e073691830ee389`.
Each archive includes the raw run, exact consumed input copies and independent
cleanup queries; source/input hashes were rechecked before any repair.

## Qualified repair and final replay

The tested source/fixture revision is
`026366f1dc126f7a06d21ae46c756fe1db9b36f7`. Final owner SHA-256 is
`346b2f9bb4fc6033acd330111c9f5a3da97f9597e638a76827f9c8d443ee492e`.
Worker commit `e4b15411124544d819014c978d27832414c3ddf1` was imported as
`8b3433f6d2d`; fixture bindings and the unrelated HTTP publication topology were
committed before the final runtime. The whole human guide and shared WordPress
SQLi helper retain their original bytes.

The module now honors the installation URI, registers COUNT with its existing
default one and zero-for-all behavior, resets query state per execution, and
probes before collecting with AutoCheck disabled. Expected transport, access,
HTTP and JSON failures become operation-specific check/run results. SQL NULL
remains valid for the shared helper's custom-prefix fallback, including indicator
zero. Per-row HEX extraction avoids aggregation truncation. Complete rows and
encoded byte pairs are validated before the unchanged credential/loot/reporting
helper receives data; malformed counts cannot become an empty successful dump.

The identical 49-case focused suite runs **42 failures original -> zero fixed**,
with zero pending or outside errors. The bounded HTTP, SQL evaluator and
persistence boundaries are doubles; real Common query generation, decoding,
WordPress prefix discovery and reporting arguments execute. Four benign fixture
bodies were independently rechecked byte-for-byte against native captures.
Additional malformed data, delimiter/UTF-8 and state-reset cases are explicitly
synthetic, adding no target-version coverage. The pre-decoder-guard draft fails
three expanded cases: odd HEX, nonhex fields and a nonnumeric row count. All
three now abort before credential or loot persistence. Strict original/final
RuboCop, msftidy, syntax and whitespace checks pass with no offenses or warnings.

The genuine final serial run is `20261116T074654-b71787`:

| Profile | Cases | Public calls | Native HTTP requests | Result |
|---|---:|---:|---:|---|
| Root | 7 | 14 | 17 | Pass |
| Subdirectory | 5 | 10 | 17 | Pass |
| Custom database prefix | 5 | 10 | 17 | Pass |
| Aggregation limit 96 | 5 | 10 | 17 | Pass |
| Patched 3.6.2 | 3 | 6 | 17 | Pass |
| Absent plugin | 3 | 6 | 4 | Pass |
| Unrelated HTTP service | 3 | 6 | 2 | Pass |

All 31 cases, 62 public calls and 91 independent native HTTP requests meet their
contracts, with zero pending examples or outside errors. Thirty-two complete
credential dumps produce 32 exact loot files and 44 exact credential rows across
16 positive workspaces. Repeated executions preserve full hashes and datastore
options. Negative paths create no credential or loot. Native before/after
controls preserve account hashes, lead data, schema and plugin source bytes.

An independent final assessor rehashes all **100 union declared inputs** against
the current tree and validates each actual inspected container's limits, init,
PID cap, restart count and OOM state. At most three containers run concurrently;
all memory/swap limits are equal. Before/after counters show no OOM or PID-limit
event. All seven exact projects and the global container inventory are empty,
and the shared advisory lock is free after sealing. No unrelated image or
volume pruning is performed.

| Immutable final profile seal suffix | Entries | Manifest SHA-256 |
|---|---:|---|
| `depicter-20261116T074654-b71787` | 138 | `ae6af621f1837e4944eeda83d93b8ba55026842c541940d332e3e090b3ef4cdd` |
| `depicter_prefix-20261116T074654-b71787` | 141 | `86bac69a419e56ce02916e33bcc2c437fb7c62c74845b266c01fa2a8f3d821dc` |
| `depicter_table_prefix-20261116T074654-b71787` | 141 | `34ae523eb4a6141b027d5f67caa815f098c7ee1963cdd118f5989c0a9257b3e0` |
| `depicter_low_limit-20261116T074654-b71787` | 141 | `c86574eaa6fd6097214fe6ae8792446860bf4165ccc80bec8b6f50ee623d0f54` |
| `depicter_fixed-20261116T074654-b71787` | 131 | `f3a05cbab8ccf32ab0c1ad4d49ca781e5157b1d54ebf85208b6b4205f7917098` |
| `depicter_absent-20261116T074654-b71787` | 131 | `0a490026d8232c43fee3513e5a975edf017d8c83845e6c7da600d641a508825b` |
| `depicter_unrelated-20261116T074654-b71787` | 130 | `ce0893ccdb27f335db8bf4de55b31d6aefd457f200537d93e05bd1cc49164c95` |

Final archives use prefix `depicter-` and suffix `-seal` around the listed
profile/run suffix. Each contains its raw profile, aggregate runner evidence,
consumed inputs and fresh cleanup audit. Sibling profile data is sealed once in
its own archive. The 296-entry source repair archive's manifest SHA-256 is
`a20eb9e7b45171a971d5dec9377ef9b740e6ff7a928a16d38e7703f6758ac5f8`;
parent verification rehashes all entries and confirms the exact file set. Final
preflight's 153-entry manifest SHA-256 is
`b2a6963162789a88cea871b85bc8eef1d90a8255f0c2f14121f3cd9939f98841`.

A fresh static inventory reports 5,179 source files, 4,622 selectable module
candidates, 262 registered sources, 4,337 pending candidates and 243 pending
container hints. There are 26 target reviews and zero stale reviews. The 4,894
pending source entries include 557 payload/support components. Registration and
qualification remain separate; the historical one-source registration/runtime
count difference is not attributed to this module.

## Review

**Summary:** The scoped repair and genuine seven-profile replay are complete.
**What looks good:** Native controls distinguish fixture corrections from source
failures, exact credential/loot comparisons catch truncation, and repeat runs
preserve target state. The shared helper and human guide are unchanged.
**Concerns:** Other release/runtime combinations and multi-schema or unusual
WordPress prefix layouts are untested. Synthetic malformed responses establish
error contracts, not additional product-version exploitability.
**Suggestions:** Keep those broader shared-prefix questions for a separate
native investigation. No blocker remains for the qualified profiles. The
broader module campaign remains open; no PR is created.


## Shared strict-result revalidation

The [Photo Gallery checkpoint](VERIFICATION-20261116-photo-gallery.md) replays
all seven Depicter profiles against the optional shared MySQLi result validator.
Depicter owner SHA-256 is
`d7f43ba35c49d23d580a9c622753f1a3cb923b161d60e1642762eac684146fd9`;
Common SHA-256 is
`9217006659e6392d5829d437dc04a035b2106c448f40cdfd3c517b04f23a3e48`.
The original local decoder, SQL-text count guard and row wrapper are replaced
by `strict_results: true`; default library behavior stays unchanged.

All seven profiles pass all 31 cases and 62 public calls at fixture revision
`1394c0b8fe7`. Thirty-two exact loot files and 44 workspace credential rows
match native values. All 91 independent native HTTP controls pass, including
the fixed release's authenticated normal lead listing and injection refusal.
Every one of the 102 union declared inputs matches current bytes. Actual caps,
zero restart/OOM/PID-limit events and exact project/global cleanup pass.
No additional owner, profile or case is counted.

The retained 49-case source suite is byte-identical and passes before/after
shared-library adoption. The new 37-case library contract suite and existing
31-case Common suite also pass on the final source. Their source selection,
comparative failures, unchanged baseline lint finding and complete immutable
receipts are documented in the Photo Gallery record. The original seven
qualification seals above retain their historical inputs; these fresh replay
seals are referenced by the Photo Gallery checkpoint. The whole human guide
and shared WordPress SQL helper remain unchanged.
