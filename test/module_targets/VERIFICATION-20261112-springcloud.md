# Spring Cloud Config verification — 2026-11-12

## Summary

The [serial lab](springcloud_config/README.md) qualifies
`auxiliary/scanner/http/springcloud_directory_traversal`. The campaign reaches
**222 modules, 230 profiles and 2,284 functional examples**. The broader
campaign remains active.

Tested revision: `442880370455d1e1db6b55078e5782a9e1ffc2a0`.
Final run: `20261112T231949-a9c4a9`. The original manager and observer both
exited 0. All **42 cases and 84 public module calls** passed, with no pending
examples or errors outside examples. Independent controls made 108 HTTP requests.

| Profile | Search location | Cases | Public calls | Exact loot files |
|---|---|---:|---:|---:|
| 2.1.8 | Relative | 7 | 14 | 12 |
| 2.1.9 | Absolute | 7 | 14 | 0 |
| 2.2.2 | Relative | 7 | 14 | 12 |
| 2.2.3 | Absolute | 7 | 14 | 0 |
| 2.1.8 control | Absolute | 7 | 14 | 0 |
| 2.2.2 control | Absolute | 7 | 14 | 0 |

## What looks good

Both release branches from the [Spring advisory](https://spring.io/security/cve-2020-5410/)
are covered. Eight embedded server/client libraries match Maven Central byte
hashes. Distribution manifests, layers and executable archives are pinned;
the original Spring `ConfigServerApplication` runs through its original Boot
loader. The functional fixtures do not simulate controllers, resource repositories or
successful responses.
Unused JDBC/security backends are excluded through supported configuration.

The exposed setup follows the vendor regression's relative `file:./` search
location. Real Spring-class probes established its difference from an absolute
location before HTTP testing. Native affected/fixed controls independently
verified ordinary configuration and traversal behavior. Every final profile
must serve both ordinary configuration and an ordinary resource. Outside-file
controls run before and after the public cases and compare exact bytes.

The module previously used the environment endpoint. Public baseline
`20261112T230410-7ef992` proved five failed existing-file cases on 2.1.8 and six
failed collection/refusal cases on 2.2.2. There were **13 actual owning calls**.
The 2.2.2 module saved ordinary configuration JSON, including for a missing file.
HTTP 200 and a saved loot path were therefore false evidence of collection.

The owner now requests the explicit-label resource endpoint and selects its
binary response with `Accept: application/octet-stream`. It URI-encodes file
bytes, validates status/body/content type and stores binary loot with the
requested filename. Genuine empty files remain successful zero-byte downloads.
Application, profile and label selectors are configurable. Existing `DEPTH`
remains registered with its default and an explicit deprecation: it has no
effect on this absolute-path primitive. RPORT remains 8888 through DefaultOptions.

Independent native testing caught a proposed shortcut before publication:
the default-label route returned 406 for a root-level file, while the explicit
label returned its exact bytes. The final public cases verify root files,
ordinary properties/text, spaces and Unicode, all 256 binary octets, empty
files and missing-file refusal. Each case runs twice. The 24 exact loot files
include four binary and four zero-byte files; fixed and unexposed profiles
produce none. Source archives, proof contents and target process identity remain
unchanged, and session/job registries stay empty.

The identical 24-case focused suite, seed 541020, changed from **17 failures /
exit 1 to zero failures / exit 0**. These are assertions, not 17 independent
native defects. It discloses HTTP and loot-persistence doubles, while owner
initialization, URI helpers and Rex wire serialization remain real. Captures
retain provenance, including the root-route ambiguity and false-positive JSON.
The functional run separately proves real transport, file contents and loot.

Two containers run serially, capped at **1,024 MiB, 1.8 CPUs and 384 tasks**.
Only target HTTP is published on loopback. Read-only host caches avoid importing
new target layers into Docker storage; temporary target storage is capped at
128 MiB. Preparation verifies all archive/library hashes and repaired an
intentionally altered cached archive. No persistent Docker volumes are needed.
Final OOM/PID-limit counters are zero. All **42 independent resource-absence
queries** passed. Docker is empty. The cleanup guard exited 0, its PID is absent
and its lock is free. No broad image or volume pruning was performed.

Reproduce serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/springcloud_config/run.rb

SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec \
  spec/modules/auxiliary/scanner/http/springcloud_directory_traversal_spec.rb \
  --seed 541020
```

The immutable final evidence has **667 entries and 53 inputs**, manifest
SHA-256 `10d845d74355f23bb65591477fbbc250d51e0edba0037b43dfd21e46a2ae1143`.
The independently copied source archive has 223 entries, manifest
`d9d89a39679398ba63ec8d0ec0a250611ae515ccd3389ac59de7c0f63bea27ce`.
All file hashes, read-only modes and single links were independently verified.

## Concerns

The fixed-release fixtures refused even an ordinary resource under the relative
location used by the vendor regression, while their configuration endpoint
worked. Their original preflights failed before any module call; these were
not module verdicts. Final fixed profiles use healthy absolute locations.
Additional absolute-location controls on both affected releases also refuse
traversal. Version and configuration are recorded separately, rather than
attributing a configuration change to the version fix alone.

Earlier failures remain separate: an unused JDBC backend initially prevented
startup; absolute locations did not reproduce traversal; a missing binary
mount point stopped four profiles before execution. All were cleaned. The
audited mount-failure seal has 311 entries, manifest
`ed5e90b5a65d072249750d64ef1e5508b4cfb0d41e438b54a877800c678a28d5`.
The public baseline has 403 entries, manifest
`f4893586aa4b0fcd1e0fb4c342b1e72a0156bc0143223bae93b65082b752266c`.
The image tagged 2.1.6 reported embedded library 2.2.1 and was not counted as
2.1 coverage.

Older releases, other repository providers, authenticated deployments and native
context-prefix/custom-selector/quote-filename cases remain unqualified. Focused
request tests cover selectors, prefixes and literal quotes without claiming
native execution. The current lab verifies Linux absolute paths and the native
filesystem provider. Registry access and a host archive cache are required.

Changed Ruby passes strict RuboCop and syntax; owner MSFtidy and module-doc checks
pass. The human Scenarios remain byte-exact, SHA-256
`51588d3fa640e0409dcbb8eaadcd8a663468b9afe1c26457cf37da41d0f1edd1`.
The full RSpec suite was not run.

## Suggestions

Continue the broader inventory: 5,179 source files, 224 registered sources,
280 pending documented container hints and zero stale reviews. Missing hints
do not establish infeasibility. The three historical exclusions
(`druid_js`, `superset_rce_owner`, `wordpress_admin`) remain unchanged.
Review Dolibarr contact collection as the next feasibility candidate.
No pull request has been created.
