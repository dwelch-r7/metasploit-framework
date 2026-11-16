# Duplicator file-read validation, 2026-11-16

All six genuine profiles pass **30 functional cases and 63 public module
calls**. Thirty-six loot files match independent target file sizes and SHA256
values, including six zero-byte files. Missing files, native unsupported quoted
paths, fixed code, absent plugins and an unrelated HTTP service create no false
loot. This adds one runtime owner and six profiles, advancing recorded campaign
coverage to **258 owners, 393 profiles and 3,358 functional cases**. Earlier
families retain their recorded inputs and scope; this is not a whole-campaign
replay of the current checkout. The broader campaign remains open. No PR is
created.

| Profile | Release / mode | Install path | Cases | Public calls | Run |
| --- | --- | --- | --- | --- | --- |
| `duplicator` | 1.3.26 | / | 8 | 17 | `20261116T010946-5ca542` |
| `duplicator_minimum` | 1.3.24 | / | 8 | 17 | `20261116T011101-3a91a5` |
| `duplicator_prefix` | 1.3.26 | /wordpress | 8 | 17 | `20261116T011215-551c87` |
| `duplicator_fixed` | 1.3.28 | / | 2 | 4 | `20261116T011326-eef835` |
| `duplicator_absent` | absent | / | 2 | 4 | `20261116T011447-c4d479` |
| `duplicator_unrelated` | unrelated | / | 2 | 4 | `20261116T011547-afbe1b` |

## Genuine setup and independent controls

The recipes reuse pinned WordPress 5.2.4 / PHP 7.3.11 and MariaDB 11.2.2. They
install checksum-pinned official Duplicator 1.3.24, 1.3.26 and 1.3.28 ZIPs;
[the release catalog](duplicator/releases.json) records archive sizes and hashes
and four installed source hashes per release. Vendor PHP is not replaced.
[Wordfence's original analysis](https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/)
and the official 1.3.28 source identify the fixed download validation and removal
of the unauthenticated init hook. Official 1.3.27 ZIP and SVN URLs returned 404;
that release is not runtime-qualified.

Vendor activation creates its package table. Four standalone native probes
pass before final owning-module qualification: affected 1.3.24 and 1.3.26, fixed
1.3.28 and a deeper fixed-handler positive control. The latter uses the genuine
DUP_Package save/getByID APIs and an owned SQL marker to prove that a valid
ID/hash download still works. It does not claim to build a full backup. These
four probes contain 45 recorded native HTTP controls, make zero owning-module
calls and have 272 independently rehashed archive entries.

The final six profiles add 46 independent native HTTP controls alongside the
63 public calls. Controls inspect actual installed code, normal login pages,
package persistence, exact file bytes and download headers before calling the
owner. ASCII/binary, UTF-8 and whitespace paths, relative paths, wp-config.php,
ordinary confined downloads, empty files and refusals are covered. The legacy
plugin retains WordPress's added slash in quoted filenames; native requests
cannot read that fixture, so tests require a clean refusal. Recorded account,
plugin and file snapshots agree before and after the owning calls.

## Preserved failures and source repair

Original production source SHA256 is
`70e1c80a4666b4d2d1a2cbdb85a7139a6ae55e39380b9790128d79bb96845537`.
Three original public attempts and their 27 calls remain sealed:

- Initial root: eight cases / three failures / 12 calls. Two failures expose
  unsupported public check and rejected empty attachments. One is a test-helper
  error: Ruby interpreted an unbraced positional hash as keyword arguments,
  stopping the negative case before its request.
- Corrected root, unchanged production: eight cases / three failures / 13 calls.
  The negative case now proves that the module saves the real 29-byte
  `Invalid installer file name!!` refusal as loot. Native positive files and
  empty attachments work independently.
- Fixed 1.3.28: two cases / two failures / two calls. Public check is unavailable,
  and the real 15-byte `Invalid request` refusal is printed and saved as a file.
  The genuine plugin stays healthy and its native controls pass.

The repair exposes Scanner's check_host dispatch, uses the actual `duplicator`
plugin slug and fixed 1.3.28 boundary, and returns reason-bearing version results.
Downloads require an attachment filename and binary content type. A present
Content-Length must match actual bytes; valid absent-length responses are
accepted. Arbitrary file contents are not classified by matching error text.
The module preserves its existing loot identity and binary bytes, saves empty
attachments, and handles expected transport failures with operation-specific
messages. The generator discovery marker is retained; the existing actual and
legacy dictionary entries remain unchanged.

A separate worktree runs the identical 41-case suite with seed 7721: original
PID 70905 exits 1 with 33 failures; repaired PID 71017 exits 0 with zero failures,
pending cases or outside errors. HTTP, UI, loot/reporting and Framework-event
boundaries are doubles; scanner dispatch, replicants, WordPress parsing,
Rex versions and HTTP response objects are real. Protocol variants without
length or Content-Description are synthetic boundaries, not a native proxy
qualification. An initial 19-failure test-helper attempt is retained: the
helper initially expected Auxiliary's failure state instead of Scanner's real
AttemptFailed contract. No production fix was attributed to that helper error.

The primary checkout also passes the default focused invocation: 48 examples,
zero failures, consisting of the same 41 owner contracts and seven existing
DatastoreFormatting examples. Those seven are not new module coverage.

Final strict RuboCop on all six changed Ruby files has zero offenses. Module
msftidy, syntax, diff and exact generator-discovery checks pass. Original module
lint exits zero at the convention threshold but retains one informational
ModuleMissingAutocheck baseline finding; it is not described as zero offenses.
The whole human module guide, including Scenarios, remains byte-identical.

## Resources, provenance and reproduction

Runtime source SHA256 is `187c74e065555e612e6ee8b56d078f9ef9be8b3391c545144fd417eff21d257e`.
The recipes are committed at `e9114117574` and the imported repair at
`6761f597bb4`. All six passing profiles use the same source and current declared
inputs. The final six seals contain **634 rehashed entries**.

Each WordPress profile uses two containers: app 0.5 CPU / 384 MiB and database
0.5 CPU / 512 MiB. The unrelated profile uses one 0.25 CPU / 128 MiB container.
Memory and swap limits are equal, each has a 128-PID cap and init, and published
ports bind only to loopback. Actual inspections confirm these caps. Recorded
OOM and PID-limit counters are zero. No sessions or background jobs remain.

The serial controller completes successfully. All 36 independent final cleanup
queries pass, including global inventory and the exact project/network/volume
identities; the advisory lock is free and Docker is empty. Original and native
probe cleanup checks are preserved separately. Unrelated images and volumes
are not pruned.

From the Framework root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/duplicator/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb duplicator duplicator_minimum duplicator_prefix duplicator_fixed duplicator_absent duplicator_unrelated
```

The [component guide](duplicator/README.md) describes prerequisites and controls.
The read-only checkpoint is
`/Users/dwelch/.codex/reports/duplicator-qualified-checkpoint-20261116`.
Its 34-entry manifest SHA256 is
`9f566b375816f987c17d30ded2142332ef3f1e3d0671c86c006adbf67ebc2d59`. It references 14 sealed archives;
all 1,361 referenced entries were independently rehashed, including the
130-entry worker repair seal and all failed attempts.

Fresh inventory records 5,179 sources, 4,622 module candidates, 259 registered
sources, 4,340 pending candidates, 245 pending documented container hints,
26 individual reviews and zero stale reviews. Registration alone is not runtime
qualification. Untested limits include unavailable 1.3.27, other WordPress/PHP
versions, multisite, TLS and genuine intermediary deployments.

## Review

**Summary:** The reproduced check, empty-file and false-loot failures are repaired.

**What looks good:** Genuine positive and refusal controls precede public calls;
all selected inputs, exact loot bytes and resource/cleanup evidence agree.

**Concerns:** The explicit version and deployment limits above remain unqualified;
no material defect remains in the selected paths.

**Suggestions:** Follow publication CI and continue the pending module inventory.
