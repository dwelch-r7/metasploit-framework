# Piwigo credential disclosure qualification

All seven profiles pass **37 functional cases and 65 public module calls**.
Genuine affected versions, a subdirectory installation, an empty gallery,
patched 13.7.0 and an unrelated service are tested separately. Successful
collection must persist the exact native username/hash pairs in real Framework
PostgreSQL storage. Correct console output alone cannot pass.

## Targets and measured results

The [component guide](piwigo/README.md) provides preparation and guarded serial
commands. The [release catalog](piwigo/releases.json) pins official 13.4.0,
13.5.0, 13.6.0 and 13.7.0 ZIPs and critical source hashes. A pinned PHP 7.3.11 /
Apache runtime comes from the existing WordPress image, with its entrypoint
replaced; WordPress is not installed or served. Piwigo source is unchanged.
The normal web installer creates the schema. Vendor APIs create member accounts,
an album and a source-generated ordinary PNG; the empty profile omits the album
and photo. No application response is simulated.

| Profile | Cases | Public calls | Native HTTP | RSpec seconds | Actual run |
| --- | ---: | ---: | ---: | ---: | --- |
| `piwigo` | 7 | 12 | 24 | 71.0 | `20261115T203720-e2591e` |
| `piwigo_prefix` | 7 | 12 | 24 | 68.7 | `20261115T203919-07dd96` |
| `piwigo_13_4` | 7 | 12 | 24 | 74.1 | `20261115T204100-ca3bab` |
| `piwigo_13_6` | 7 | 12 | 24 | 66.5 | `20261115T204246-e6d0e1` |
| `piwigo_fixed` | 3 | 6 | 19 | 53.6 | `20261115T204422-cfe7e7` |
| `piwigo_empty` | 4 | 7 | 21 | 56.7 | `20261115T204546-ee608d` |
| `piwigo_unrelated` | 2 | 4 | 1 | 44.8 | `20261115T204711-f7e466` |

All final invocations exit zero with no failures, pending or outside errors.
Timings include cold console startup and native controls; build/setup is separate.
**137 independent native HTTP controls** precede owner calls. CLI runs as the
web user and checks actual PHP/product/source identity and database account rows.
The entire extracted host source tree and original ZIP are hashed before and
after testing. Native HTTP proves valid/rejected login, working ordinary history,
denied member access and exact scalar SQL row bytes. Patched history must work
normally before its injected input refusal can pass.

Five actual target accounts include comma/semicolon and Unicode usernames and
the default guest with a NULL password. The four nonempty hashes must match
PostgreSQL records exactly, with correct hash formats, module origin, host,
service, port and protocol. Each example starts a fresh reporting workspace;
repeated successful runs in that workspace must retain exactly four records.
Wrong passwords, a valid ordinary member, missing paths, the patch and unrelated
products must save no credentials. Sessions/jobs remain empty. Account names,
hashes and roles stay unchanged; this is not a complete database audit.

MariaDB's real session `group_concat_max_len` is 96 bytes. Native SQL establishes
that the account collection exceeds this and the aggregate truncates. Independent
HTTP scalar queries still retrieve every complete row. The repaired module uses
Framework's existing HEX/per-row SQLi helper so those five accounts suffice to
exercise truncation and delimiter cases without populating a large slow gallery.
The empty gallery's ordinary identification page supplies a passive version
fallback; collection succeeds with both default AutoCheck and explicit bypass.

## Preserved failures and source repair

The first native SQL probe used quoted literals that the application escaped;
its HTTP 200 contained a MySQL error. It is sealed with zero module calls before
correcting the probe. Later native 13.5/13.6 disclosure and 13.7 refusal controls
pass. Two initial owner-recording setup errors (an unused Compose interpolation
requirement and an internal-only reporting port) also stop before Framework
calls and stay sealed as harness failures.

A real original-module 13.5.0 recording runs check, default run and two forced
runs with PostgreSQL connected. The displayed administrator hash is correct,
but actual stored `private_data` equals the username. The guest is also saved as
an invented nonreplayable hash. This proves a reporting defect independently
of the later aggregate-limit fixture.

The first public seven-case run has three failures after native gates pass:
truncated collection, missing login session with AutoCheck disabled, and a test
that demands abort wording from a legitimate member refusal. The latter is a
bad expectation; accepting explicit refusal while checking empty storage fixes
it. Revised original run `20261115T203222-90b9c9` then has **7 cases / 2 failures**,
24 passing native controls and ten completed public actions. It also retains the
actual corrupt/truncated stored credentials. Native login separately proves that
correct credentials without a session cookie are rejected; GET then POST works.

Separate-worktree commit `82e127cc060` integrates as `83ffea21742`. The repair
persists extracted hashes, omits NULL/empty private hashes, uses the existing
scalar/HEX/safe SQLi API, starts a fresh login session independently of check,
and handles expected HTTP failures. Passive checks cover the source-supported
13.2.0 through 13.6.0 range, with the fix in 13.7.0. 13.2/13.3 are source-reviewed
and synthetic boundary cases, not additional native runtime qualifications.
Original owner SHA256:
`9bbbad3a776fd24cf01f86397e96953115766823984339cff090461bcc35c03f`.
Final owner SHA256:
`a0904a4e8a1dad3c25a31d05992a8ad30602de21c30f9271a83beb1d19d22e09`.

The first fixed native recording has correct complete output and four exact
stored hashes, but two assertions fail because console transport is ASCII-8BIT
while expected usernames are UTF-8. That run is sealed before decoding unchanged
console bytes as UTF-8. No module change follows that harness correction. The
final default run passes all seven cases; the other six final profiles use the
same corrected helper. The original and final native helper versions therefore
differ in explicit text decoding; this is not an identical-input native pair.

The identical focused unit suite/seed 7721 gives **29 examples / 23 failures on
original source, then 29 / 0**. HTTP, SQL-server, reporting and UI boundaries are
explicit doubles; actual Common query generation/decoding, hash identification,
version/path/error behavior and AutoCheck run. Six sanitized HTTP projections
are independently rehashed against the original immutable native receipt.
Synthetic versions/rows/hashes are labeled. An initial fixed draft's Encoding
constant error is separately retained before correction. Unit results add no
native runtime qualification.

Strict module RuboCop and msftidy retain one identical baseline metadata-name
whitespace offense (exits 1 and 2 respectively); no new offenses or suppressions.
Syntax and diff checks pass. Five new fixture/spec Ruby files have zero strict
offenses. Primary default selection passes 45 distinct examples: 29 Piwigo,
nine unchanged Simple Backup and seven existing formatting examples. The
functional bridge is excluded and no support examples are selected twice.
No full local suite is run. The whole existing module guide, including human
Scenarios, remains byte-identical. Custom database table prefixes, other PHP
runtimes, TLS and unlisted target releases remain untested.

## Resource and evidence checks

One stack runs at a time, at most three containers. Actual inspect data confirms
app 0.5 CPU / 384 MiB / 128 PIDs, MariaDB 0.5 CPU / 512 MiB / 128 PIDs and
PostgreSQL 0.5 CPU / 256 MiB / 128 PIDs. Unrelated Apache uses 0.25 CPU / 128 MiB;
its profile has only two containers. All use init. Before/after OOM/PID counters
are zero and no target is OOMKilled. HTTP/reporting ports are random loopback;
MariaDB stays internal. Host Framework runs under nice outside target cgroups.

**42 independent cleanup queries and seven released locks** establish all
20 exact containers, 14 networks and 19 volumes absent. The serial batch checks
these before starting the next profile. Unrelated images/volumes are preserved.
All seven full input maps match at initial qualification. Only component README
qualification prose is updated after those seals; runtime source, tests, recipes,
archives and extracted-file manifests remain identical. This documentation-only
difference is explicitly recorded instead of claiming a complete current-tree
replay. Earlier campaign targets are not replayed for this checkpoint.

The seven final read-only exports contain **602 independently rehashed entries**.

| Local export under `/Users/dwelch/.codex/reports/` | Manifest SHA256 |
| --- | --- |
| `piwigo-20261115T203720-e2591e-sealed` | `3c52f6f0bc1b72e7a5125b5fef096073668888b0daacbe9c3687879295b3c179` |
| `piwigo_prefix-20261115T203919-07dd96-sealed` | `6ab27dc0e5bc9280dc2492a477efb293d830d655d8a89b6cc775c68d033a2c8f` |
| `piwigo_13_4-20261115T204100-ca3bab-sealed` | `346d739270a06e905bdf819250d892b88ddca90a834dfc6013a920c5effc5910` |
| `piwigo_13_6-20261115T204246-e6d0e1-sealed` | `61597ff1abd51a03246aa4afbe15a671446d11420ea5d8cf50a0bb69b42ca83d` |
| `piwigo_fixed-20261115T204422-cfe7e7-sealed` | `59118e1b8409d0ac010fb01df1a0592c428560c22d698f605af8dde959d5b01d` |
| `piwigo_empty-20261115T204546-ee608d-sealed` | `855b0d04ae234d7ce5d84d1d15f1be4a2d0f4055285dba64de8cb5a9557982b4` |
| `piwigo_unrelated-20261115T204711-f7e466-sealed` | `aeef1282a53aa3d10e7683e85453982016b0c04816dd25da801af208f92acaf2` |

The source repair export `piwigo-reporting-repair-20261115` contains 134 rehashed
entries; manifest SHA256
`f27937f54b903f2f9463279eb5afef82da5f69c71791b645ae402de7724bc4ff`.
The corrected original public recording has manifest
`820bdde3e6b0fb61aeb9cb446081289bc07eaaf76286c7258410e4d2e68b7d52`.
The first fixed encoding-failure recording has manifest
`ad2ccbaa180f5e3c82585afaa3fe51b37a1e331271f47cec549b52e03acbdf9a`.
Private native/setup/preparation predecessors remain separate and unqualified.

This adds one owner, seven profiles and 37 cases to the frozen recorded coverage:
**255 runtime owners in covered paths, 375 profiles and 3,255 functional cases**.
The broader campaign and prior investigations remain open. Publication CI
observations have a [separate provenance-scoped record](VERIFICATION-20261115-publication-followup.md).
No PR is created.
