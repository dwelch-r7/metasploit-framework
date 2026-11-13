# Dolibarr contact collection verification — 2026-11-13

## Summary

The [serial lab](dolibarr/README.md) qualifies
`auxiliary/scanner/http/dolibarr_16_contact_dump`. The current campaign reaches
**223 modules, 235 profiles and 2,306 functional examples**. The broader campaign
remains active; these counts do not establish completion of the full inventory.

Tested revision: `f083e80ccef13f928a972c30d2fd9fe1f36052eb`. Final run: `20261113T103832-73405d`.
The final manager and observer both exited 0. All **22 cases and 44 public module
calls** passed, with zero pending cases or errors outside examples. Independent
controls made 130 HTTP requests; 24 exports match native data.

| Target | Cases | Calls | Exact loot files |
|---|---:|---:|---:|
| 16.0.4, root | 5 | 10 | 12 |
| 16.0.4, `/crm` | 5 | 10 | 12 |
| 16.0.5, default ticket settings | 5 | 10 | 0 |
| 16.0.5, optional ticket lookup enabled | 5 | 10 | 0 |
| Unrelated static PHP website | 2 | 4 | 0 |

## What looks good

Both original Dolibarr source archives are pinned to immutable commits and
checksums. Twenty-one installer, authentication, model, database and disclosure
files per release are checked against original source. PHP 5.6.40 is in the
[vendor's supported range](https://wiki.dolibarr.org/index.php/Releases).
The mysqli extension builds offline from the pinned official PHP source;
a fresh rebuild produced the same compiled checksum. Preparation repaired a
deliberately damaged cached source file. No binary or application dependency
is added to Framework.

The genuine CLI installer creates the database and administrator. Original
models create, delete and restore the company and three contacts. Controls
verify wrong-password refusal, successful administrator login, actual database
rows, exact-email and unknown-email lookups. Anonymous requests carry no
administrator cookies. No vulnerable responses, controllers or permission checks
are simulated. Vendor code and extension mounts are read-only; configuration
is locked after installation. Process identity and configuration hashes remain
stable, and collection leaves database rows unchanged. Restored contacts acquire
new real IDs and can be collected again.

The original public baseline `20261113T002132-ed7996` had **22 cases, five failed
assertions and 39 actual public calls**. JSON was complete, but CSV stripped
outer whitespace and final newlines from genuine public/private notes, both
before and after model restoration. The unrelated site was falsely reported as
Dolibarr `Detected`. Fixed defaults and enabled lookup controls already refused
the module's bare `%` request; those were not failures.

The owner now preserves exact CSV scalar text, including Unicode, quotes and
line breaks, while retaining full native JSON objects and connection metadata.
An unversioned `Detected` result requires Dolibarr-specific page metadata.
Unidentified, inaccessible and missing check responses return `Unknown`.
Disclosed-version comparisons and the existing bare-percent lookup stay intact.
Port 80 remains the default; duplicate host prefixes are removed.

The identical 15-case focused suite, seed 33568, changed from **nine failed
assertions / exit 1 to zero / exit 0**. HTTP responses and loot persistence are
doubles; initialization, JSON parsing and CSV generation/parsing are real. A
parent review caught and corrected a projection that initially represented
native newlines as literal backslash-n text. Earlier comparisons are retained.
The primary worktree independently passes all 15 cases. Real transport and saved
loot are verified separately by the container tests.

Application profiles use **three containers capped at 1,408 MiB, two CPUs and
448 tasks**. The Framework cap is 640 MiB; the unrelated profile uses
two containers capped at 704 MiB, 1.3 CPU and 320 tasks. Preparation uses
one offline container capped at 384 MiB, 0.7 CPU and 96 tasks. Only application
HTTP is published on loopback; there are no persistent Docker volumes. Source
and compiled-extension caches stay under ignored `tmp/` paths. Main cases repeat
twice. The first console is cold; later profiles use only that invocation's
normal cache. Actual prompts, BOOT records and both cache files are observed.

All **39 independent final cleanup queries** pass. Docker is empty; the cleanup
guard exited 0, its PID is absent and its lock is free. No broad image or volume
pruning was performed. All final memory-limit, OOM and PID-limit counters are
zero. The Framework cap was raised from 512 to 640 MiB after the earlier cold run recorded pressure.

Reproduce serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/dolibarr/run.rb

SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec \
  spec/modules/auxiliary/scanner/http/dolibarr_16_contact_dump_spec.rb \
  --seed 33568
```

Final evidence: 635 files and 48 pinned inputs, manifest
`8ece1120d0bba6346bdc25256ed018a1953b607daa34092b336bd555731eb714`.
The source comparison has 155 entries, manifest
`21098fc00228b90d03e8e1a12183edb25a437d27a5cda2a28d3b73f90b6951e5`.
All copied file hashes, read-only modes and single links are verified.

## Concerns

With the optional lookup feature enabled, genuine 16.0.5 still returned matching
contacts for `%@example.invalid`, although its bare `%` request returned no
contacts. This is residual application behavior outside the module's current
request. The passive `Safe` assessment does not prove every lookup pattern is
safe. Investigate separately; no new attack mode is added here.

Earlier setup failures remain distinct: a 256 MiB database cap stalled installation;
512 MiB and bounded database caches completed. A login request without Referer
was correctly rejected by CSRF protection. The fixed default endpoint returns
HTTP 200 with an access-denied HTML body, rather than the initially expected
403. The first extension build used a nonexecutable tmpfs and failed; the
corrected offline build succeeds. None of those attempts established a module
verdict.

The repaired application run `20261113T101748-d2c046` passed all four application
profiles, then refused the unstarted static-site profile after seeing an
unrelated `postgres:16` container. Daemon events show that container existed for
about one second and was destroyed. A separate cold static-site run
`20261113T102559-2193a9` passed both cases. The matrix manager and observer exited 1
for that setup refusal; the separate manager/observer exited 0. These
results are retained independently from the final documented-input replay.
Their manifests are `f1ab71525102f2abf5a8ad32b8a1c3f0967da06653a7a9629a7bd910ada9d696`
and `5a80d0ceca11fbf8f474bc29533c3ceed6d7005e7c655a6cc71d85f3dc971193`.
The first cold Framework container recorded 78 memory-limit events, with no OOM;
all other containers recorded zero. No target-memory failure is inferred.

The user restarted Docker while run `20261113T103129-8f4ec2` was active.
The manager and observer were stopped with interrupt status 130. The partial
report has one failed case and one outside-example error after Docker API HTTP
500 and a refused native connection; these are infrastructure interruption
evidence, with no module verdict. All eight exact cleanup queries pass after
the engine returns. The 103-file interruption seal has manifest
`8bd52f4322c0ac9f260bd3953a49502d6cbbf007e92be6e5dea7f015eb5e7403`.
Transient-container refusals before preparation created no module run. The
task-local final controller required five consecutive empty inventories before
starting the canonical manager and observer together; this is separate from
the portable lab launcher above.

Changed Ruby passes strict RuboCop and syntax, and owner/module-doc checks pass.
The entire historical Scenarios-through-EOF tail is byte-exact, SHA-256
`5e1504858f6cbd1fbf83de4196348057471bb2a455a5f62347567e309f25e993`.
The full RSpec suite was not run. Earlier 16.x patches, later releases, other PHP
versions/database providers and other lookup patterns remain unqualified.

The previous published revision `d4c94af2a8163e20029a74e3544410a3c0bc9893` has
62 successful checks, one skipped check and one failing
[Linux Mettle job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43329514765/job/131570400642).
Its 51-example suite timed out during intermediary-directory creation in
`post/test/file` over reverse HTTP with `base64_transforms.profile`. Root cause
and causality remain unverified. It is not a Dolibarr acceptance failure.

## Suggestions

Continue the full source inventory: 5,179 files, 225 registered sources, 279
pending documented container hints and zero stale reviews. Missing container
hints do not establish infeasibility. The three historical exclusions
(`druid_js`, `superset_rce_owner`, `wordpress_admin`) remain unchanged.
Review Concrete CMS file-usage disclosure next; its documented target has been
read, but image/runtime feasibility is not yet verified. No PR has been created.
