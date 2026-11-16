# Planyo local file collection validation

Status: native affected/fixed calibration complete; original module filename
failure confirmed; repair and functional qualification pending. This record
adds no runtime coverage counts. Seven profiles and 34 cases are drafted in
[the lab](planyo/README.md).

## Genuine targets and native controls

Unmodified official Planyo 2.9 and 3.1 archives activate on WordPress 6.8.3 /
PHP 8.3.28. Pinned archive and installed proxy/plugin/readme hashes establish
source identity. The directly accessible `ulap.php` is a genuine standalone
vendor file proxy; the remote reservation product is outside this test scope.
The 3.1 source introduces an HTTP(S)-only scheme guard and removes localhost
from its host allowlist. Source 2.7 is also pinned; its runtime profile remains
pending. The actual readmes list changelogs in ascending order, so choosing
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
The separate repair worktree is addressing only file URL/request encoding.
The original human guide and Scenarios remain byte-protected. All functional
qualification and new coverage counts are pending. No PR is created.
