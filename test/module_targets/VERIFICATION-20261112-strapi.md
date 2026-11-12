# Strapi password-reset verification — 2026-11-12

## Summary

The [Strapi lab](strapi/README.md) qualifies
`auxiliary/scanner/http/strapi_3_password_reset` against genuine
3.0.0-beta.17.4 and fixed beta.17.5. The campaign reaches **221 modules,
224 profiles and 2,242 functional examples**. The broader campaign remains active.

Tested revision: `ecf9af086a5df6a9b801632af714eb4e2d12f833`.
Final run: `20261112T223517-d4935f`. The original manager and observer both
exited 0. All **12 cases and 24 public module calls** passed, with no pending
examples or errors outside examples.

| Release | Cases | Public calls | Successful resets | Stored credentials |
|---|---:|---:|---:|---:|
| beta.17.4 | 6 | 12 | 4 | 4 |
| beta.17.5 | 6 | 12 | 0 | 0 |

## What looks good

Independent native controls proved registration, incorrect/correct login,
legitimate scalar-token resets, token consumption and malformed-token behavior
before Framework testing. Both release fixtures additionally passed these
controls during the final run, including a complex Unicode password. No HTTP
success response, authentication service or database query is simulated.

An administrator needs an unused pending reset token. Tests explicitly seed
the ordinary database field to establish that prerequisite; the module does
not initiate a reset request. Native controls prove that fresh and consumed
tokens are refused. The affected release accepts the object token twice;
the fixed release refuses it twice while preserving the password hash and token.
The vendor [fix](https://github.com/strapi/strapi/pull/4443) establishes beta.17.5
as the fixed release.

Public cases cover version checks, ordinary and complex passwords, absent and
consumed tokens, and no administrator. Every case runs twice. Independent logins
verify rejection of the previous password and acceptance of the exact new one.
Actual PostgreSQL rows verify the username, exact password, module origin,
service, TCP protocol, host and port. The fixed target retains account state
and stores no credentials. Account restoration permits subsequent execution;
session/job registries stay empty and the target process does not restart.

The baseline exposed genuine source defects: a successful reset raised
`KeyError` because credential reporting omitted `protocol`, and a Unicode
password produced a truncated HTTP request. Real Rex serialization declared
120 bytes while emitting 122. The owner now validates a copied UTF-8 password,
serializes JSON as octets, supplies TCP reporting data and guards response types.
It preserves datastore bytes and encoding. Shared HTTP/Rex code is unchanged.

The old public check was unsupported because the Scanner API requires
`check_host`. The intended passive check now reports `Appears` for the proven
affected release, `Safe` from beta.17.5, and `Detected` for unverified earlier
releases. Check capability was a gap, not a native exploit regression.

The identical 19-case focused suite, seed 91427, changed from **14 failures /
exit 1 to zero failures / exit 0**. Nine original failures concern check
capability. Unit HTTP delivery, credential persistence and UI are explicit
doubles; JSON, real Rex wire serialization, owner initialization and the Scanner
check wrapper remain real. The final functional run separately verifies actual
HTTP delivery and persistence. The failed draft `Encoding` namespace correction
is preserved separately and is not attributed to the original source.

Pinned npm lockfiles reproduce original packages. Thirteen authentication,
bootstrap, route, model and query files per release match official tag hashes.
Preparation rejected an intentionally altered cached file, ran `npm ci` and
restored its exact original bytes. Dependencies are cached on the host and
mounted read-only during functional tests. The original generator's MIT license
is retained. Browser frontend serving is disabled through a supported setting;
genuine backend routes, JWT/password services and MongoDB models remain active.

Four containers run serially, capped at **1,664 MiB, two CPUs and 512 tasks**.
Preparation uses one container capped at 768 MiB, 0.7 CPU and 128 tasks. Only
target HTTP is published on loopback; capped temporary filesystems hold writable
application/database state. Final OOM and PID-limit counters are zero. All
**18 functional and 33 dependency-container absence queries** passed. Docker's
complete container inventory is empty. The cleanup guard exited 0, its PID is
absent and its lock is free.

Reproduce serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/strapi/run.rb

SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec \
  spec/modules/auxiliary/scanner/http/strapi_3_password_reset_spec.rb --seed 91427
```

The immutable final evidence has **602 entries and 82 inputs**, manifest
SHA-256 `a633d74440c9e8d6726bb4b0833b5066dbe855cb4efc7705465aa2ce6a147483`.
The independently copied source regression archive has 119 entries, manifest
`bb9373ead3a6a3a8efd17d490629b2d740f2f56aba343df0ce10970b67e3319b`.
All file hashes, read-only modes and single links were independently verified.

## Concerns

Earlier setup failures remain distinct from module verdicts. Initial incomplete
apps omitted necessary model/JWT dependencies or configured the ORM incorrectly.
One fixed-release dependency install was actually OOM-killed; an interrupted
installation also produced an invalid lockfile. Clean, memory-bounded
installation followed by successful `npm ci` resolved preparation. An initial
native control compared MongoDB's extended-JSON ID with an API string; the actual
reset had succeeded and the corrected comparison passed. None qualifies a module.

Baseline `20261112T220359-bf2666` had three affected and two fixed-profile
failures, separately sealed before repair: 580 entries, manifest
`4af51b34e242556a2b9314939be435deed6f6364b7784f4d91c026186f3784a3`.
It independently demonstrated successful reset followed by reporting failure,
real target request-parse errors and the unsupported check capability.

SMTP delivery, browser administration, older releases, other database providers
and historical Node versions remain unqualified. This lab uses Node 22.23.4 and
MongoDB 4.4.30 with original vendor packages. The Docker backing filesystem is
full; host dependency caches avoid duplicate image layers. No broad image or
volume pruning was performed.

Changed Ruby passes strict RuboCop, syntax and module MSFtidy. Documentation
retains one identical pre-existing line-three whitespace warning. Human Scenarios
remain byte-exact, SHA-256
`379b6f6b4efbc64dc0d2fe21f5fc18a6beebc05154598b40528bec7d4ec0d5d9`.
The full RSpec suite was not run.

## Suggestions

Continue the broader feasibility inventory: 5,179 source files, 223 registered
sources, 281 pending documented container hints and zero stale reviews. Missing
container hints do not establish infeasibility. The three historical exclusions
(`druid_js`, `superset_rce_owner`, `wordpress_admin`) remain unchanged.
Spring Cloud Config traversal is a candidate for the next native feasibility
review. No pull request has been created.
