# Simple Backup file disclosure qualification

All five genuine profiles pass **23 functional cases and 48 public module calls**.
Their 26 exact loots include twenty traversal disclosures and six ordinary
confined backup reads. Two confined reads run on 2.7.11; they do not establish
traversal exploitability. A separate scanner-hook repair exposes the existing
version check while preserving the download method.

## Targets and measured results

The [component guide](simple_backup/README.md) provides preparation and guarded
serial commands. It reuses the pinned WordPress 5.2.4 / PHP 7.3.11 image, bootstrap,
database and archive helper. [Official ZIPs and handler hashes](simple_backup/releases.json)
pin genuine Simple Backup 2.7.10 and 2.7.11. WordPress APIs install and activate
unchanged vendor code. An owned backup directory and ordinary backup file supply
the download prerequisite; no handler or HTTP response is simulated.

| Profile | Cases | Public calls | Exact loots | RSpec seconds | Actual run |
| --- | ---: | ---: | ---: | ---: | --- |
| `simple_backup` | 8 | 17 | 12 | 41.2 | `20261115T192827-4d463a` |
| `simple_backup_prefix` | 8 | 17 | 12 | 43.6 | `20261115T192952-108f36` |
| `simple_backup_fixed` | 3 | 6 | 2 | 38.4 | `20261115T193137-8da5c1` |
| `simple_backup_absent` | 2 | 4 | 0 | 38.3 | `20261115T193251-8e06d6` |
| `simple_backup_unrelated` | 2 | 4 | 0 | 36.3 | `20261115T193402-36ea04` |

Every final invocation exits zero with no failures, pending cases or outside
errors. Timings include native controls and cold console startup; build/setup
time is separate. Isolated host configuration and metadata caches are fresh.
**38 raw HTTP controls** execute before owner calls. Web-user CLI inspection
verifies actual versions, archive/handler hashes, activation and readable bytes.
The fixed control refuses the tested traversal requests while independently
serving an ordinary depth-zero backup. Plugin absence redirects the genuine
administrative endpoint to login. Unrelated Apache has its own checked marker.

Affected cases repeat system, binary, configuration and ordinary backup reads.
Unicode, whitespace, apostrophe and relative paths preserve exact target bytes,
including UTF-8, NUL and 0xff. Each success creates one fresh loot with the actual
length and SHA-256. Empty/missing files and insufficient depth produce no loot.
Both installations use depth 6 for the filesystem root, depth 1 for WordPress
configuration and depth 0 for a confined backup. Native empty content cannot
prove successful disclosure, so it is a negative control.

The configured WordPress rewrite rules also route a nonexistent URL prefix
through the active plugin. A fresh independent HTTP request verifies exact
disclosure before the corresponding owner case; access logs confirm the requested
prefix. This selected deployment behavior is a positive case. Absent/unrelated
deployments are separate real negative controls. Repeated checks must actually
be supported: Appears for 2.7.10, Safe for 2.7.11 and Unknown for the negatives.
An unsupported-check message cannot pass a negative case.

## Preserved failures and source repair

The first native-only probe incorrectly expects quoted-path refusal. Actual
HTTP returns the exact 29-byte quoted fixture. That failed probe stops after six
HTTP requests with zero owner calls and is sealed before correction. Corrected
2.7.10 and 2.7.11 native comparisons each pass eleven HTTP controls with zero
owner calls. They establish prerequisites and add no functional qualification.

Original public run `20261115T192356-46b146`, exec 46388, exits one with eight
examples/two failures, eleven native controls, sixteen completed commands and
twelve exact loots. One failure is the genuinely unsupported public check. The
other incorrectly expects a nonexistent URL prefix to refuse a file. The access
log shows that exact request receiving 200, and the fresh loot equals the native
system file. The next suite adds an independent raw HTTP gate for this route.

Corrected original run `20261115T192658-16af8b`, exec 31240, has eight examples/
one failure, twelve passing native controls, sixteen commands and twelve exact
loots. All seven file cases pass; only the public check remains unsupported.
This original recording is sealed before integrating the repair.

`MultipleTargetHosts#has_check?` requires `check_host`; the original owner instead
overrides `check`. Separate-worktree commit `7e4e81305e4` integrates as
`1ece83d0081`, exposing `check_host(_ip)` and following mixin order. The inherited
public API remains. The entire `run_host` suffix is byte-identical, SHA-256
`25440ab438b9c84e5e578da6f01b486e63f6cb9ea8ab750be0e38d6224bde4de`.
Original owner SHA-256:
`6dd0d7bb1e35ca4a3adcfc10c8c5f38deb7910a9d09d3c7f70083aa80e3d83e1`.
Repaired owner SHA-256:
`66367ece92f47a3eff9e4e769dad7e458835646446849dd49530ca7f1246f65e`.

The identical final focused suite/seed 7721 gives **nine examples/eight failures
on original source, then nine/zero**. A separate pre-edit capability proof is
retained. HTTP, lifecycle, reporting/events and listener boundaries are doubles;
actual public dispatch, validation, real replicants, version extraction and Rex
comparisons execute. The affected readme projection comes from the official ZIP,
explicitly labeled archive-derived; fixed/missing/unversioned unit inputs are
synthetic. This is not a native worker result or eight independent defects.

Strict owner lint retains eight identical baseline offenses, down from nine
because the missing-AutoCheck complaint disappears. There are zero new offenses
or suppressions. Tidy, syntax and diff checks pass. Five fixture/new-spec Ruby
files have zero strict offenses. Primary default selection passes 25 distinct
examples: nine Simple Backup, nine GI-Media and seven existing formatting tests.
The functional bridge is excluded, support tests are not selected twice, and no
full local suite is run. Existing module documentation/Scenarios are unchanged.

## Resources and evidence

One stack runs at a time: app 0.5 CPU / 384 MiB / 128 PIDs and database 0.5 CPU /
512 MiB / 128 PIDs; unrelated Apache uses one container at 0.25 CPU / 128 MiB /
128 PIDs. All use init. Actual caps match; before/after OOM/PID-limit counters
are zero with no OOMKilled flags. Only random loopback HTTP is published; the
database stays internal. Host Framework processes run under nice outside target
cgroups. File bytes, active plugins and administrator password/activation-key
fingerprints stay unchanged; this is not a full database audit. Sessions/jobs
remain empty and ordinary audit logs persist until teardown.

Thirty independent cleanup queries and five released locks establish nine exact
containers, nine networks and eight volumes absent. Docker is empty between
stacks and after the last run. All five selected input maps still match current
source/helpers/archive bytes. Read-only local exports under
`/Users/dwelch/.codex/reports/` retain **522 independently rehashed final entries**.

| Export directory | Manifest SHA-256 |
| --- | --- |
| `simple_backup-20261115T192827-4d463a-sealed` | `fc2a7a80b76691c3c87fe12f7130e459f67cadfe9734ead1f671c0c194019ed1` |
| `simple_backup_prefix-20261115T192952-108f36-sealed` | `443ee4fe2538fc63c28f762ea36499ea592ab0100b37d45bb810f34cf41f6d5d` |
| `simple_backup_fixed-20261115T193137-8da5c1-sealed` | `b1dd0703570def246f80daaff83d147450c40eaff191e32729a0cacee7eb28a0` |
| `simple_backup_absent-20261115T193251-8e06d6-sealed` | `38d081fd489935e89ae93dca457e796d53c5b57479ceb4b70cfd16f79a651099` |
| `simple_backup_unrelated-20261115T193402-36ea04-sealed` | `9012019972ffccc6707ffb10a4db0ebdd34f03c7c4f2741791dd8fc4d50e00dc` |

The three native predecessors and two original public recordings retain 424
additional rehashed entries, without adding qualification. The source-repair
export `simple-backup-scanner-check-repair-20261115` has 78 rehashed entries;
its `MANIFEST.sha256` hash is
`f317cc808057e053b66451ac6c1bf4ce97e75f3079c2a70c925ee1c4ebac0e1c`.
The corrected original public export has manifest
`955fbdbeca30fc71aebdff1bd46bcae6ef268e115567bad90820010b3740517a`;
the earlier two-failure public export has
`5e48343c755f8968346388a9338c0da4fa45be3898e73ed142489ba0186b94a9`.
The native quoted-path stop has
`8d7c421b79c4fcbeb642bde8dfbfd177e780c4d45085e6245bfbc74d2e3223a6`.

## Recorded checkpoint and remaining scope

Recorded coverage reaches **254 runtime owners in covered paths, 368 profiles
and 3,218 functional cases**, adding one owner/five profiles/23 cases to
[GI-Media](VERIFICATION-20261115-gimedia.md). Earlier families retain their frozen
inputs; this is not a whole-campaign replay. Static inventory records
5,179 sources, 4,622 selectable candidates,
255 registered owners, 4,344 pending candidates,
248 pending container hints and 26 reviews
with 0 stale. Registration is not proof of qualification.

Only the selected releases/runtime, requests and deployment state are qualified.
Other plugin/core/PHP releases, content directories, transports and filesystem
layouts remain unqualified. Tested fixed refusals are not a complete vendor
patch audit. Baseline lint findings, the staged PHP reconnect investigation and
broader campaign remain open. [POST SMTP publication CI](VERIFICATION-20261115-post-smtp-publication.md)
separately records its unresolved Linux native timeout. Newer publication heads
have their own CI follow-up. No PR is created.
