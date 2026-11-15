# DukaPress file disclosure qualification

All five genuine profiles pass **18 functional cases and 38 public calls**,
including twelve byte-exact file loots. The original module downloads files but
its public scanner check is unavailable. The repaired check hook passes affected,
fixed, absent-plugin and unrelated-server checks without changing the download
method. This adds one runtime owner and five profiles.

## Reproducible targets and actual results

The [component guide](dukapress/README.md) provides archive preparation and guarded
serial commands. Genuine WordPress 5.2.4/PHP 7.3.11 runs official checksum-pinned
DukaPress 2.5.3 and 2.5.4. The pinned Linux/amd64 WordPress image supports the
original plugin's historical PHP APIs. WordPress APIs install/activate the
unmodified vendor code. No HTTP route, file-read response or version result is
simulated. The unrelated control is genuine Apache.

| Profile | Cases | Public calls | RSpec seconds | Actual run |
| --- | ---: | ---: | ---: | --- |
| `dukapress` | 6 | 13 | 40.7 | `20261115T182427-082116` |
| `dukapress_prefix` | 6 | 13 | 41.4 | `20261115T182633-669d56` |
| `dukapress_fixed` | 2 | 4 | 36.7 | `20261115T182757-a14092` |
| `dukapress_absent` | 2 | 4 | 41.8 | `20261115T183033-c589bb` |
| `dukapress_unrelated` | 2 | 4 | 32.6 | `20261115T183221-5d02e9` |

Every final result has zero failures, pending cases and outside errors. Timings
include native controls and cold console startup; build/setup time is separate.
The documented multi-profile invocation can reuse metadata between serial stacks.
These qualifications use fresh invocations and isolated host console state.

Native CLI inspection runs as the web user and records installed versions,
archive/endpoint/resize-source hashes, actual account state and file bytes,
readability and lengths. Independent HTTP then proves exact affected disclosure
or fixed refusal before owner actions. Across the five profiles,
31 native HTTP requests are recorded separately from public commands.

Success must create one fresh loot whose length and SHA-256 match the native
file. Tests repeat real `/etc/passwd` and binary-file reads, preserve UTF-8/NUL/
0xff content, read a Unicode pathname containing spaces, and handle a relative
pathname. Empty/missing files, insufficient depth, missing installations and
natively refused quoted paths must produce no claimed download. Checks must
actually be supported and return the affected/fixed/Unknown assessment; a
`does not support check` message cannot pass a negative check. File state,
password/activation hashes and plugin state remain unchanged. Ordinary web/PHP
session audit artifacts are allowed until teardown; no account password changes.

Root traversal uses depth 7. The `/wordpress` installation uses 8 for the extra
level. This is explicit deployment configuration, rather than a source fix.
The original endpoint cannot distinguish an empty file from a failed read, so
empty-file responses are negative controls, not positive disclosure proofs.

## Original failure and focused repair

Two native-only release comparisons first establish genuine 2.5.3 file reads
and 2.5.4 refusal. Two original host-console recordings then confirm exact
50-byte UTF-8/NUL loot on affected source and no loot on the fixed target. Their
`check` actions report unsupported; those recordings establish download behavior
and capture completion, not successful checks or automated qualification.

The first full-suite attempt stops before any owner action: it incorrectly
requires disclosure of an existing pathname containing an apostrophe. Native
HTTP does disclose the separate 51-byte binary fixture exactly, but returns 200/
empty for the quoted path despite native existence/readability. The sealed run
`20261115T180822-694a6f` has six failed examples and zero owner calls. This is a
native expectation error, not a module failure.

[WordPress 5.2.4 request handling](https://raw.githubusercontent.com/WordPress/WordPress/5.2.4/wp-includes/load.php)
adds escaping to request values and reconstructs `$_REQUEST`. The original
plugin consumes that value without unslashing before opening a path. Subsequent
inspection records the installed core helper's actual transformed pathname,
while HTTP verifies refusal. The fixture keeps an ordinary Unicode/space path
as a positive case and treats the quoted path as a native limitation for these
requests. It does not alter WordPress or the plugin to manufacture success.

The corrected original run `20261115T181127-7b4e8f` passes all five file cases but
fails the check case: **six examples, one failure, twelve completed public
commands**, all native prerequisites and cleanup passing. The scanner's
`MultipleTargetHosts#has_check?` requires `check_host`; the owner defines `check`.
Console capability discovery consequently refuses to invoke it. Static inventory
presence of a check method does not prove this public interface works.

Separate-worktree commit `89c22b04355` integrates as `d8a1300532b`. It exposes
`check_host(_ip)` through the existing scanner dispatch and follows the declared
mixin order. The inherited public `check` API and original version-helper result
are retained. **The entire download-method suffix remains byte-identical.**

Original owner SHA-256:
`f65e29d56a3660c235666e023020b098e324286826c019aa33b20ad701d39853`.
Repaired owner SHA-256:
`ca0a36713a33d35d842fa4de8c39971e557c6b14de71dcd44b4d0ed805f23808`.
The identical final focused suite/seed 7721 reports **nine examples/eight failures
on original source, then nine/zero on the repair**, with zero outside errors.
Original direct Ruby checking remains a passing control while public capability
and replicant dispatch fail. HTTP, setup/cleanup, reporting and framework events
are explicit doubles; validation, real public `check_simple`, replicants, version
extraction and Rex comparisons execute. Minimal fixed/missing/unversioned inputs
are labeled synthetic boundaries. These are not eight separate native defects
or additional functional cases. An initial missing Framework datastore double
is retained with its exact pre-correction inputs.

Strict owner lint retains seven pre-existing offenses: three Notes, two string
literals, regexp style and the zero-length predicate. Original source has eight;
the old missing-AutoCheck complaint disappears with the proper scanner hook.
**Zero new offenses** are introduced, and no suppressions/style sweep are used.
Module tidy, syntax, docs tidy and diff checks pass. Six existing guide warnings
were corrected before Scenarios: the opening heading and four inline code fences.
Six component/helper Ruby files and
the new owner spec have zero strict-lint offenses. Primary default-CI selection
passes 68 examples: nine new owner checks, 52 POST SMTP/helper regressions and seven
existing formatting examples. This functional bridge is excluded. No full local
RSpec suite is run. Human module Scenarios through EOF are byte-identical,
SHA-256 `7f8108bc99b102217f4033bb207d0a920bdadc671c2f5387435e2b0c0a96b449`.

## Shared recipe and modern compatibility

The common WordPress Dockerfile accepts `WORDPRESS_IMAGE`, retaining its exact
previous default 6.8.3/PHP 8.3 image pin. The DukaPress component supplies the pinned
legacy image through that argument and reuses the same genuine core bootstrap,
database and initialization helpers. Pinned plugin archive preparation is
extracted from POST SMTP into one shared WordPress helper; existing cache names,
checksum/atomic-download behavior and global resource lock remain.

A real modern POST SMTP replay after those changes passes its original **four
cases/seven calls** with actual core 6.8.3/PHP 8.3.28, SMTP delivery, valid reset keys,
exact loot and explicit state restoration. Run `20261115T180311-b4ff46`, original
exec 40300, has zero failures and successful exact cleanup. Its 62 recorded inputs
and 104-entry export are retained separately. This replays existing coverage and
adds no unique cases, owners or profiles. Earlier families retain their frozen
inputs; the shared change is not represented as a whole-campaign replay.

## Resources, cleanup and retained evidence

WordPress uses 0.5 CPU/384 MiB/128 PIDs and MariaDB 0.5 CPU/512 MiB/128 PIDs.
Four WordPress profiles use two containers each. Unrelated Apache uses one at
0.25 CPU/128 MiB/128 PIDs. All use init. Only application HTTP is published on a
random loopback port; the database stays on an internal network. Framework uses
the existing host bundle with isolated configuration under `nice`; its processes
and memory remain outside target cgroups.

All nine actual container inspections match their intended limits and have no
OOMKilled flag. Every role has before/after zero OOM/PID-limit counts; memory
boundary max events remain informational. Empty console jobs/sessions and
**thirty independent cleanup queries plus five released locks** establish all
nine exact containers, nine networks and eight volumes absent. The global
inventory is empty between stacks and after the final run. All five final input
maps match current source and selected cached archive bytes.

Read-only local exports under `/Users/dwelch/.codex/reports/` retain 483
independently rehashed final entries: actual native CLI/HTTP, raw binary console,
result, resource and cleanup records, exact loot and frozen inputs. Raw console
logs deliberately contain 0xff and should be read as bytes; a read-only diagnostic
UTF-8 decode error did not alter them or indicate an execution failure.

| Export directory | Manifest SHA-256 |
| --- | --- |
| `dukapress-20261115T182427-082116-sealed` | `be5550fffd63854a3f37cfd1296de7bd309eade8388c8c984fb7774d77a5c9cb` |
| `dukapress_prefix-20261115T182633-669d56-sealed` | `f00da3db42f1e0f982bbd0f95e69d928bf897c601d382b5d89bcef0386c2d919` |
| `dukapress_fixed-20261115T182757-a14092-sealed` | `7f1e20962ca819d75d19e5b96e23a310812769d4ad3b1b06fe61b6bef22035e3` |
| `dukapress_absent-20261115T183033-c589bb-sealed` | `41071f91c74864b4d97132cccc2b9b312da580c0dba311fbb109b9d80cd0f33f` |
| `dukapress_unrelated-20261115T183221-5d02e9-sealed` | `dfc0d4739e0a57954aff0bd7a501eabc681757c38057281acba381f20f92af79` |

The source-repair export `dukapress-scanner-check-repair-20261115` has 105 rehashed
entries. Its `MANIFEST.sha256` hash is
`e0ce8d05563bd26378a956ecbf464ecafc034dafa11a830dbf86563c0385e907`.
The original unsupported-check run has manifest
`749c8433ae90e319caf2772eedce28c702493fd2601cf5da473034818866a763`;
the earlier native quoted-path stop has
`7a8cf34ed3c7daa6a531c191bd34f7e94e1b7bafbf674a621fd047a23e112ef1`.
Native-only and original-console predecessors remain separately sealed and add
no automated qualification. The modern replay's manifest is
`09c1a2208d0c39235e0dafd8e8eab1337cc531050f5460608cf6a3b3ee6850f9`.

## Recorded campaign checkpoint

Recorded coverage reaches **252 runtime owners in covered paths, 358 profiles
and 3,175 functional cases**. Only the five final DukaPress profiles/eighteen cases
are added; repeated calls, original/native-only runs, focused units and modern
replay cases are not recounted. TLS, multisite, other releases/runtimes and
architectures remain separate coverage. The broader inventory and staged PHP
session investigation remain open. The preceding pushed POST SMTP checkpoint's
[exact fork Ruby 3.3 unit job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43743237368/job/132900792464) passes 19,439 examples/zero failures/33 pending; its
native CI jobs are still tracked separately. No whole-campaign replay,
completion or PR is claimed.
