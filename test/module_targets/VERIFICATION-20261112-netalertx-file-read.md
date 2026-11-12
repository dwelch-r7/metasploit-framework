# NetAlertX file collection verification — 2026-11-12

## Summary

`auxiliary/scanner/http/netalertx_file_read` is qualified on four genuine Linux
amd64 image/configuration pairs: **32 examples, 64 public module calls, zero
failures, pending cases or outside-example errors**. Thirty-two stored loot files
match independent native file bytes. Protected 24.10.12 refuses anonymous access
and produces no loot. The campaign reaches **217 qualified modules, 212 profiles
and 2,182 functional examples**. Registration covers 219 sources; 285 documented
container hints remain pending and no review is stale.

Two production module defects were reproduced and fixed: the scanner now exposes
`check_host`, making public `check` available, and structured JSON serialization
preserves quoted filenames. The final owner SHA-256 is
`190102bae55f234dfb6fd3bd7ffda9afa246f552b2a14617237e0b445a8e80ce`.
The tested commit is `0ccae4d327f283243a34ade0caaf208f7006fe3a`. The module guide adds
only a reusable-lab link; human Scenarios remain byte-exact.

| Profile | Protection | Examples / failures | Exact loot files | RSpec duration |
|---|---|---|---|---|
| netalertx_24_9_12_protected | Enabled | 8 / 0 | 10 | 105.364 s |
| netalertx_24_9_12_public | Disabled | 8 / 0 | 12 | 69.213 s |
| netalertx_24_10_12_protected | Enabled | 8 / 0 | 0 | 42.430 s |
| netalertx_24_10_12_public | Disabled | 8 / 0 | 10 | 60.280 s |

All final profiles run serially in `20261112T170844-60ca34`. Each pins 44 current
inputs, 50 distinct across the matrix. The manager and independent observer both
exit zero. The first console has an independently observed cold prompt, BOOT and
two fresh metadata snapshots. Later consoles use only that invocation's verified
seed. No manual cache was supplied.

## What looks good

[The reusable target guide](netalertx_file_read/README.md) and `vendor.json` record
both image digests and their exact source revisions. Static image inspection and
runtime hashes agree with the actual shipped PHP/backend code. No application
source, endpoint response or version value is replaced.

The fixture calls the vendor's real database migrations, notification-table
initializer, configuration importer and API generation. It serves the real PHP
application using the shipped NGINX template and FPM configuration, with bounded
worker counts. Discovery loops and cron stay stopped. The optional initial
release check uses a refused loopback proxy so its unbounded external request
cannot stall setup. Runtime processes confirm no scanner/backend loop is running.

Before owning calls, native HTTP controls verify configured protection,
wrong/correct login, authenticated maintenance/version access, and exact reads
of controlled files outside the web root. Files contain HTML metacharacters,
spaces and a quote in the filename; empty and missing files are distinct
negative controls. SQLite integrity and real initialized settings are checked.
All four native version/authentication profiles pass independently before the
functional matrix, then repeat before and after each profile's owning calls.
Source hashes, bootstrap identity, database settings and exposure remain stable.

Functional cases repeat explicit checks, ordinary AutoCheck, forced collection,
disabled AutoCheck, zero traversal depth, spaced and quoted filenames, and
missing/empty files. The protected maintenance endpoint's redirect remains an
Unknown check result. That result does not imply that the affected logs endpoint
is safe: forced collection proves the bypass on 24.9.12. Its quoted-path
regression now stores exact bytes instead of sending malformed JSON.

The final SQL audit verifies 32 distinct loot records/files and 17 vulnerability
records with actual host/CVE context. Public affected-version AutoCheck reports
merge with the later collection report by host/service/CVE. The first record's
name and information remain; explicit auxiliary checks first report through the
failure-reporting hook before the console reporting hook. Assertions match these
observed, unchanged reporting contracts. Successful file bytes independently
establish collection; a vulnerability row alone does not.

Session/job vectors are empty before all 64 normal harness bulk reset commands.
They close no active object. All 32 final parent absence queries pass; the four
separate native profiles add 24 passing parent queries. Actual container mounts
show no anonymous volumes. Docker is empty after teardown.

Only three containers run at once, capped at **960 MiB, 1.5 CPUs and 384 tasks**:
target 192 MiB / 0.3 CPU / 64 tasks, Framework 640 MiB / 1 CPU / 256 tasks and
PostgreSQL 128 MiB / 0.2 CPU / 64 tasks. Memory/swap limits match, none is privileged,
and all native/final cgroup checks show zero OOM or PID-limit events. Only random
loopback HTTP is published; application state is temporary.

The new functional spec passes strict RuboCop and its tagged dry run selects
exactly eight cases. Ruby syntax, shell/Python syntax and module documentation
checks pass. No full RSpec suite was run.

## Concerns

The 24.10.12 patch adds endpoint authentication. With web protection explicitly
disabled, the ordinary file-reading endpoint remains accessible. The matrix
preserves that real configuration behavior rather than treating the version
number as universal proof of refusal. Default AutoCheck still marks that version
Safe; deliberate override or disabling AutoCheck exercises the accessible path.

The original module baseline has two genuine failures: public checks are rejected
because scanner support requires `check_host`, and an unescaped quote corrupts
its hand-built JSON. The same target/file succeeds through correctly encoded
native HTTP. The focused source fix was developed and committed in a separate
worktree, independently reviewed, then validated through all four genuine profiles.

A subsequent matrix exposed test-reporting assumptions, not new module defects:
auxiliary failure reporting writes the first explicit-check row, and database
reference matching merges AutoCheck/collection records. Exact failed inputs and
captures remain sealed separately. Early native setup attempts also caught missing
startup prerequisites and a generated environment-key error before any module
verdict. Those failed attempts are retained with cleanup evidence.

Strict module RuboCop exits 1 before and after the fix with the same two existing
warnings: leading whitespace in Name and duplicate RPORT registration. MSFtidy
exits 2 from those same findings; no new offense is introduced. The functional
spec and documentation checks are clean. Published CI is recorded separately
for its exact commit; no PR was created.

This qualifies the file-collection web path on these exact image/configuration
pairs. Other releases, architectures, mounted paths, discovery features and
NetAlertX command execution remain separate work. Existing Druid, Superset
RCE-owner and WordPress-admin exclusions remain unchanged.

## Suggestions

Use the serial command in [the target guide](netalertx_file_read/README.md).
Keep native authentication/file controls, source identity and exact loot bytes
before interpreting a failed check or run. Preserve human Scenarios.

Next, evaluate `exploit/linux/http/netalertx_rce_cve_2024_46506`. Read-only source
review confirms that it needs the real backend, settings importer and cron queue
restart path, which this web-only fixture intentionally does not run. Validate
that native execution, backend identity and cleanup independently before owning
sessions. Keep discovery disabled and avoid changing these qualified inputs.
No RCE target has been launched or execution verdict assigned.

Private immutable evidence:
`/Users/dwelch/.codex/reports/netalertx-file-read-verified-20261112` has 478 manifest
entries and 50 distinct input files. Manifest SHA-256:
`d5b18a71a8bcddd660deb798f6bc5e9a25f8c4c1fe972bb620e0bbc8fdddb8ef`.
Every file's hash, read-only mode and single link count was independently checked.
Separate immutable bundles preserve the original module failures and the later
reporting-fixture failure. Transient lab addresses and captures stay private.
