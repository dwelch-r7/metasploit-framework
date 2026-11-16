# Depicter native calibration, 16 November 2026

Status: native target calibration passed; owning-module functional qualification
is pending. These results add no owner, profile or functional-case counts yet.

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
The shared WordPress SQLi helper and module guide remain untouched. A module-local
repair is in progress in an isolated worktree; final qualification is pending.

The immutable root/prefix/low-limit/fixed evidence archives contain respectively
221/224/224/224 entries. Their manifest SHA-256 values are respectively
`3bfaccf462f6621f629eceee16e0cc0e2963fdb7f75871660d0fa3644fa9422c`,
`f6d577e144ca34ae7af66f3d5594db39f8c0d7a7ff5c1f1c950043fb83770716`,
`6ad1484f7d9c6d11da660639c0556a75592ddf89a04f302be5805b6448adf5f2`, and
`6304f02aeb67350d78ff8cd48a642bf83b48abfae1f77a806e073691830ee389`.
Each archive includes the raw run, exact consumed input copies and independent
cleanup queries; source/input hashes were rechecked before any repair.
