# Forgejo verification — 11 November 2026

The checkpoint is **204 qualified modules, 167 profiles and 1,817 passing
functional examples**. The [Forgejo lab](forgejo_file/README.md) adds five serial
profiles for `auxiliary/gather/forgejo_orgmode_fileread_cve_2026_59774`.
The campaign remains incomplete: 297 documented container hints need review,
alongside unhinted candidates. Registration of 206 sources is not qualification.

## Targets and result

The vendor fixes are [15.0.6](https://codeberg.org/forgejo/forgejo/pulls/13683)
and [16.0.2](https://codeberg.org/forgejo/forgejo/pulls/13682). Pinned source
commits, platform image identities and binary hashes are in
[profiles.json](forgejo_file/profiles.json). The 15.x pair uses vendor images.
The 16.x registry indexes referenced missing amd64 child manifests at inspection;
those failed resolutions are retained. The adapter retains the normal 15.0.5
vendor runtime, entrypoint and S6 wrapper, installing the genuine official 16.x
release binary with compressed and uncompressed SHA256 verification. Live image
layers, commands, labels and actual binary hashes match that declared packaging.
There is no replacement HTTP handler, Docker socket, executor or CI runner.

Final source: `0dc6e81788893959bb371f80b85ae6f391470e94`.
Run: `20261111T214014-923d4d`. Manager and all five live observers exit zero.

| Genuine target | Examples | Failures | Spec seconds |
| --- | ---: | ---: | ---: |
| Forgejo 15.0.5 | 16 | 0 | 179.78 |
| Forgejo 15.0.6 | 13 | 0 | 118.37 |
| Forgejo 16.0.1 | 16 | 0 | 138.63 |
| Forgejo 16.0.2 | 13 | 0 | 118.55 |
| Apache 2.4.62 control | 2 | 0 | 27.07 |

There are no pending examples or outside-example errors. The first console has
an observed prompt, BOOT record and two fresh metadata snapshots without a seeded
first cache. Later consoles use only the normal same-invocation seed, observed
and compared byte for byte.

Native CLI/API controls independently establish accepted/rejected credentials,
ordinary rendering, public/private repositories, real filesystem content and
permission failures. Python HTTP/HTML parsing is independent of Framework and
Nokogiri. Controls also prove a refused port in Framework's actual UID/network
namespace and genuine PostgreSQL accepted/rejected authentication.

The 104 public module calls cover check, AutoCheck enabled/disabled, repository
discovery/selection, stdout/loot, repeated reads and negative paths. Root checks
all 20 successful printed bodies and 10 actual loot files against complete native
rendered text, including Unicode, large files, spaced paths and no final newline.
Fixed and unrelated targets create no loot. Missing files, directories,
unreadable files, empty/whitespace content, invalid repository/quoted paths,
invalid credentials and refused connections do not produce false read success.

The real database contains the expected records in 22 service workspaces and
14 vulnerability workspaces. The latter include two passive check-only records;
they are not all confirmed reads. Framework's check and AutoCheck records have
different names/evidence, and later reports can merge by reference. Assertions
preserve those actual contracts. HTTP services have correct names, addresses,
ports and state, with version information retained after checked reads.

Native pre/post controls preserve file, account, repository, configuration and
binary state, target process identity, and Apache content/identity. Memory/PID
event counters remain clean. All **67 distinct selected input hashes** are current.

## Original failures and correction

The first mixed run, `20261111T210610-2a5d4c`, has 60 examples/14 failures:
ten fixture expectations about passive/automatic database reporting and four
genuine module failures. After correcting only those expectations, clean original
run `20261111T212633-a9168a` has **60 examples/four failures**, two on each
affected release. Both fixed releases and Apache already pass. Both original
batches have passing native pre/post controls and all 44 cleanup queries passing.
Their separate read-only seals preserve the original code and failures.

- A UTF-8 HTML fragment without an embedded charset is parsed as Latin-1,
  corrupting Unicode stdout and loot: 30 native rendered bytes become 45 bytes.
  The fix gives a duplicated response/body explicit UTF-8 encoding before the
  existing HTML parser; original response bytes and encoding remain unchanged.
- A successful AutoCheck-disabled read reports a vulnerability without an HTTP
  service, leaving its automatically created service unnamed. The fix reports
  the HTTP service after confirmed content, preserving existing version info.

The identical focused suite, seed 59774, contains **32 examples**: 25 module
examples and seven existing formatter examples. Original source exits 1 with ten
failures; the first correction exposes one nil-body regression; the final source
exits zero with no failures. Root independently reruns 32/0 and verifies exact
worker module/spec/capture hashes. Captured-response doubles and labelled
synthetic nullable/transport cases complement the genuine acceptance tests.
Human Scenarios remain byte-identical. The shared console runner is unchanged.

Helpers/spec RuboCop, Python syntax, module documentation and whitespace checks
pass. Canonical module RuboCop exits 1 and msftidy exits 2 for the identical
pre-existing duplicate `RPORT` registration warning. No new finding is added.

## Fixture limits, resources and cleanup

The real org-mode API returns rendered text and removes a final newline from
ordinary text files. Empty, whitespace, missing and unreadable files may all
produce empty rendering. These tests do not claim byte-exact original-file or
binary recovery. The module's repository-context contract is retained.

Disposable users use the supported `pbkdf2$50000$50` setting to shorten repeated
API authentication. Native SQL checks verify the exact algorithm without
capturing password hashes. An earlier 256 MiB target pilot hit its memory limit;
it is not used as evidence for the final budget.

Only one project runs at a time, with three containers. Each Forgejo project is
capped at **1,408 MiB/1.45 CPUs**: target 512 MiB/0.25 CPU/128 tasks, reporting
PostgreSQL 128 MiB/0.2 CPU/64 tasks, Framework 768 MiB/1 CPU/256 tasks. Apache
projects total 960 MiB/1.3 CPUs. Live inspection verifies these limits, equal
memory/swap caps, loopback-only published ports and no privileged containers.
Each project is removed before the next starts.

The first native pilot failed before any module call because the Docker VM had
no usable disk space, despite ample host space. Scoped cleanup removed only old
campaign-tagged build images, two verified campaign-owned cached OneDev vendor
images, and two reclaimable campaign build-cache records totaling 1.709 GB.
Unrelated images and volumes were preserved; no global prune was run. Other
early setup failures concerned project-name syntax, pre-user authentication,
CLI product-name case and newline expectations. Their logs and cleanup receipts
are retained separately from module failures.

The final **44 independent cleanup queries** verify exact containers, networks,
data volumes, project inventories and an empty global container list. The actual
Docker engine/context is unchanged. A bounded local guard removes unrelated tool
containers recreated by the app, outside module coverage.

The final read-only seal has **707 manifest entries**, SHA256
`6871ce6851472ab8d20d67e58f7187ed8f2018e56736d208984b519268bc2f66`.
Identical files are hardlinked only within the package, independently of active
source/run files. Evidence is under `tmp/module-target-tests/20261111T214014-923d4d/`
and the local `forgejo-verified-20261111` seal.

## Review and remaining scope

**Summary:** Genuine affected/fixed reads, check classifications and refusal
paths pass after two reproduced module defects were corrected.

**What looks good:** Complete native text, real loot, database records, repeat
execution, current inputs and exact teardown agree across both release branches.

**Concerns:** Other versions, reverse proxies/base paths, TLS deployments and
binary file recovery remain unqualified. Existing `druid_js`,
`superset_rce_owner` and `wordpress_admin` profiles remain unqualified and
excluded. Inventory contains 18 individual reviews with none stale. New-head
CI is assessed separately; local acceptance is not a claim of green CI.

**Suggestions:** Keep further families serial and retain actual HTTP charset,
rendered text and database evidence when changing collection/reporting behavior.

Reproduce from the Framework root:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb forgejo_15_0_5 forgejo_15_0_6 forgejo_16_0_1 forgejo_16_0_2 forgejo_unrelated
```

Publication is to the user's public fork branch. No PR is created.
