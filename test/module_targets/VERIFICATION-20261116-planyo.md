# Planyo local file collection validation

Status: qualified in seven current profiles. Planyo adds one owner, seven
profiles and 34 cases, advancing historical campaign coverage to **263 runtime
owners in covered paths, 428 profiles and 3,525 functional cases**. The
[lab](planyo/README.md) retains reproducible genuine targets.

## Genuine targets and native controls

Unmodified official Planyo 2.9 and 3.1 archives activate on WordPress 6.8.3 /
PHP 8.3.28. Pinned archive and installed proxy/plugin/readme hashes establish
source identity. The directly accessible `ulap.php` is a genuine standalone
vendor file proxy; the remote reservation product is outside this test scope.
The 3.1 source introduces an HTTP(S)-only scheme guard and removes localhost
from its host allowlist. Source 2.7 is also pinned and its genuine runtime profile passes. The actual readmes list changelogs in ascending order, so choosing
the final version heading is correct for these releases.

Across the two native attempts, 22 independent HTTP requests pass. Version
2.9 returns exact native text (27 bytes), binary (14 bytes), empty (zero bytes)
and special-filename (28 bytes) data when file URL path segments and the HTTP
query are encoded separately. Actual www-data identity, file ownership and
permissions establish the controls. The denied root-owned 0600 file and a
missing file produce genuine HTTP 500 replies; ordinary WordPress stays
healthy afterward. On 3.1, all six file URLs return the vendor scheme-guard
message while the ordinary application continues to work. Neither native
attempt invokes the Metasploit module.

Users, source and fixture file snapshots agree before/after. Each attempt uses
two actual capped containers with equal memory/swap limits, init processes,
128 PIDs and CPU limits of 0.5. Inspection/counters show no restart, OOM or
PID-limit events. Exact project container/network/volume queries and global
container inventories are empty after teardown; the advisory lock is free.

| Native release | Entries | Manifest SHA-256 |
| --- | ---: | --- |
| 2.9 | 70 | `c3db87bee14233894bbcb24bb0f482d9af4ad0419f7fd55141aee09cd4abd0d5` |
| 3.1 | 70 | `f0631547da3a69dbae8c85e29beb42c764a25c21cfc43e43e85b8a58e42ea388` |

## Original owning-module observation

Original source SHA-256 is
`602508faf606b6492b4dcfa2d02fdd40b4fc951622708af415c39aca45c31266`.
The original module completes 14 public run calls: twice each for its default
`/etc/passwd`, text, binary, empty, special-name, denied and missing file.
Twelve contracts pass. Both special-filename calls fail to create the expected
loot, even though the independently encoded native request reads that exact
28-byte file. The owning wire request contains literal spaces, ampersand,
UTF-8 and a hash character in its request line and receives HTTP 400.
Console datastore bytes are independently recorded and match the intended
filename before each call. The source manually appends FILEPATH to a query
string and sends it with `send_request_raw`.

The 103-entry original observation is sealed under
`/Users/dwelch/.codex/reports/planyo-owner-corrected-input-2.9-20261116T095254-seal`;
manifest SHA-256 is
`ae25bccd923f9baeafa7d9b0b17c4d263791d48f4aab445e696982c2f6fa1646`.
Diagnostic completion is separate from the module's two failed contracts.
Actual post-owner snapshots match the baseline, and all containers are removed.

An earlier probe stops after eight matching file loots because Ruby inspection
renders the Unicode console input as a literal escape. Its input guard fails
before the special-file request, so it establishes no module defect for that
case. That 93-entry attempt remains sealed separately, manifest SHA-256
`4c2cf69b0d58e24f81be7bc9275853b4dfd29ca5f14af7ce7b8d28391cae3ca3`.
A separate probe draft fixes shell quoting and records the expected and actual
path bytes, preserving both observations. An initial archive HTTP 502 is also
retained before successful source capture; a 3.0 archive HTTP 404 is not a
runtime or general version-availability verdict.

The module has no public check, and none is promised; that is not a finding.
The original human guide and Scenarios remain byte-protected.

## Narrow source repair and contracts

Worker commit `bd804eee85ca4016d66e1ea13aba17615473d56b` was imported as
`fd78aa0fdc5`. The request block encodes each FILEPATH segment before placing
the file URL in `send_request_cgi`'s `vars_get`. Existing slashes, literal
percent sequences and filename bytes are preserved through both decoding
layers. Default collection, version/changelog gating, response handling and
code outside that request block remain unchanged.

The identical 25-case focused suite has eleven failures against the exact
original source and zero against the repair. Both sides have zero pending or
outside-example errors. Actual HttpClient dispatch and Rex request
serialization execute; discovery, connection/send-receive, UI and persistence
boundaries are explicit doubles. Eight captured readme/file responses are
independently verified against native source receipts and bytes. Additional
reserved-character inputs are synthetic URI byte roundtrips, not target
filesystem or extra-version claims.

Strict original/final module lint exits one with the same four existing
findings: three unknown Notes sentinels and duplicate RPORT registration.
The new spec has zero offenses. Original/final msftidy exits two with the same
four findings; syntax and diff checks pass. These metadata/option findings
remain separate from functional behavior and are not silently reclassified.
The 180-entry immutable source evidence archive is
`/Users/dwelch/.codex/reports/planyo-file-url-contracts-20261116`;
manifest SHA-256 is
`42c1f08fe3f0a68a2932988ca6c3fa430d5185a905ee5906b11e37b48e443616`.
The parent independently rehashed all entries, confirmed the exact file set
and matched all four imported file blobs to the worker commit.

All seven Compose configurations and the exact 34-case collection pass
preflight. Its 144-entry seal is
`/Users/dwelch/.codex/reports/planyo-preflight-20261116T101539-seal`;
manifest SHA-256 is
`3ac7acc72f3d0b3b06e967e9106de43c047d17de7a167130ed0d9d3ff767a904`.
All seven profiles pass all 34 genuine cases and 68 public calls at fixture
revision `45305e7cc12`. The root profile includes exact loot for the original
special filename and a separate literal-percent, plus, query and quote name.
Active 2.9 root/subdirectory, active 2.7 and installed-but-inactive 2.9 paths
all collect default, text, binary, empty and special-name bytes twice. The
fixed release, absent plugin, unrelated service, wrong installation path,
blank filename and actual denied/missing files save no unintended loot.

Forty-two exact loot files, including eight empty files, match native sizes,
SHA-256 and full bytes. All 156 independent native HTTP controls pass, and all
91 union declared inputs match current bytes. Actual inspection verifies at
most two containers per stack, CPU limits no greater than 0.5, equal memory
and swap limits, init processes, 128 PIDs and loopback-only published ports.
No restart, OOM or PID-limit event occurs. Native users, source and file states
agree before/after; no Framework sessions or jobs remain.

Each exact project is removed before the next starts. Container, network,
volume and global-container queries independently confirm teardown. Docker
is empty and the advisory lock is free. The increment is applied once:
262/421/3,491 becomes 263/428/3,525 owners/profiles/cases. Earlier campaign
scope remains historical. The broader campaign and four baseline metadata/
option findings remain open. No PR is created.


| Profile | Cases | Calls | Exact loot files |
| --- | ---: | ---: | ---: |
| `planyo` | 10 | 20 | 12 |
| `planyo_prefix` | 7 | 14 | 10 |
| `planyo_older` | 7 | 14 | 10 |
| `planyo_inactive` | 7 | 14 | 10 |
| `planyo_fixed` | 1 | 2 | 0 |
| `planyo_absent` | 1 | 2 | 0 |
| `planyo_unrelated` | 1 | 2 | 0 |
