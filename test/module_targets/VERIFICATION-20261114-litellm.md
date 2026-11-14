# LiteLLM pre-authentication SQLi scanner

The covered paths of `auxiliary/scanner/http/litellm_proxy_sqli` pass against
genuine affected, fixed and vendor-mitigated LiteLLM targets. This advances the
campaign to **245 modules qualified in covered paths, 303 profiles and 2,886
unique functional examples**. The broader campaign remains incomplete. No PR is
created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb litellm litellm_fixed litellm_mitigated
```

| Profile | Genuine target | Cases | Public calls | RSpec duration | Result |
| --- | --- | ---: | ---: | ---: | --- |
| `litellm` | Affected 1.83.3 | 8 | 16 | 103.97 s | Pass |
| `litellm_fixed` | Fixed 1.83.7 | 8 | 16 | 54.99 s | Pass |
| `litellm_mitigated` | 1.83.3, vendor error-log workaround | 8 | 16 | 52.64 s | Pass |

Run `20261114T162011-6d2a70` completes with the original controller and guarded
manager exiting zero. All three RSpec reports have zero failures, pending cases
and outside-example errors. The complete serial invocation takes
397.16 seconds, including setup, a cold first console and teardown.
Later profiles use metadata generated within this invocation only.

## Native target fidelity

The [recipes and controls](litellm/README.md) pin official Linux amd64 images:

- 1.83.3: `litellm/litellm@sha256:c2b7aba0e3ebac7618ed23d12c5c65e05c533fb6843a0c694ff5c77c53de3ddf`.
- 1.83.7: `litellm/litellm@sha256:f3cf1864daeea79ebdb00dafa036e3c66d182029d66b4b13befae7c5d8802554`.

Installed `proxy/utils.py` matches vendor source commits
`cf045dc6d2b9b4383703628fb26feb9769190281` and
`e0d5c28db02b3219dbd944666a55f49732197922` exactly. The parameterization fix is
[vendor commit 4dc416ee74](https://github.com/BerriAI/litellm/commit/4dc416ee749122ca91e3bca095217478663419e7);
the third profile exercises the
[vendor advisory's mitigation](https://github.com/BerriAI/litellm/security/advisories/GHSA-r75f-5x8p-qvmc),
`general_settings.disable_error_logs: true`, on the affected image.

The images use Python 3.13.13, LiteLLM proxy extras 0.4.65 and Prisma 0.11.0.
Native startup executes the vendor migrations against PostgreSQL 16.15 with
migration-failure enforcement and one application worker. The application role
has no superuser, create-role, create-database or replication privileges, and
cannot connect to the separate Framework reporting database. Real API-generated
virtual keys are verified against persisted hashes and actual management/model
listing APIs. No application route, SQL vulnerability, model response or
production owner method is replaced. The authentication-error path requires no
external provider account or inference request.

There are 114 successful native probe-process invocations and 78 independent
native HTTP/control requests. Empty, one-key and five-key tables are measured.
The affected true predicate sleeps about one second while false and hashed
`sk-` controls remain fast. The uncorrelated subquery sleeps once with five keys,
not once per row. Unicode model names preserve this genuine native signal.
Fixed and mitigated targets remain fast for the same probes. Native failures
verify refused port 1 and the actual missing route before owner negatives run.

## Module behavior and reporting

All 48 public owner calls return a reason-bearing CheckCode: ten Vulnerable,
32 Safe and six Unknown. Genuine positive `check` and `run` calls persist the
correct vulnerability name, target host, TCP port, references and proof in the
actual Framework PostgreSQL database. Repeated scans deduplicate their report.
The console's normal positive `check` command also reports a confirmed finding.

All twelve owner Unicode POSTs reach the native authentication path with HTTP
401 and a 93-byte body framed as 93 bytes. Refused connections return Unknown;
missing routes produce no vulnerability report. Repeated checks/scans, 0.5/1.0
second delay changes and model transitions retain fresh unique bearer probes.
All 48 before/after application-record comparisons match. Unauthorized requests
can append native spend/error audit records and daily aggregates; these three
explicit audit tables are retained separately and are not erased to simulate
restoration. No OS session or exfiltration is part of this scanner's contract.

## Confirmed source defects and earlier failures

The original owner sent UTF-8 JSON using character-count framing: 90 declared
characters for 93 bytes. Identical-model native requests returned HTTP 401 with
the real timing signal, while owner requests returned HTTP 400 and false Safe.
It also treated nil probe responses on an independently refused port as Safe.
Commit `3890cb7ba354b384dc81303c9d0dc6605947a8ec` sends JSON as bytes and converts
missing/expected connection failures into a logged, reason-bearing Unknown.
The true/false SQLi comparison and vulnerability reporting remain intact.
Nearby explanations now reflect the native uncorrelated sleep behavior.

The identical final focused suite gives **21 examples / 10 failures before**
and **21 / 0 after**, without pending or outside errors. It exercises the real
Rex serializer and SQLi comparison, with controlled HTTP, timing and reporting
boundaries; these are focused regressions, not additional native qualifications.
They cover both-fast, both-slow and reversed timing controls plus missing true
or false responses. Strict RuboCop on all five changed Ruby files, module tidy,
documentation tidy, syntax and Python parsing pass. Human Scenarios are preserved
byte-for-byte, SHA-256 `4909218c9b7f5e57347f6fca88c075b18a6f60d687b40809bec16ba6ee2e9b89`.

Original run `20261114T160730-5d2a17` had eight examples, five passed and three
failed. Two failures establish the source defects above; the third was an
incorrect harness expectation that positive checks do not report findings.
It was corrected using the actual Scanner behavior and stored database row.
A preceding eight-example failure occurred in native state preflight before any
module dispatch: a psql generator printed SQL before JSON. This was a harness
error, not eight module defects. Earlier private setup failures involved a host
binding on an internal network and a 1 GiB startup OOM. None is presented as a
module verdict. Evidence was sealed before edits; resources were removed.

## Resources, cleanup and retained evidence

Exactly three capped services run per profile on an internal network without
host port bindings: LiteLLM 2 GiB / one CPU, database 512 MiB / half a CPU, and
Framework 1 GiB / one CPU. The shared guard serializes profiles. Final observed
target peaks stay below 1.32 GiB. Cgroup OOM and PID-limit counters remain zero.
All 24 independent exact-ID/project/global teardown queries pass, Docker is
empty and the shared lock is free.

The read-only accepted archive is
`/Users/dwelch/.codex/reports/litellm-qualified-20261114`: 538 files,
46 selected inputs, MANIFEST SHA-256
`333bb298848613914f55dafc3d204ec14dd2f876ca7fd34122349a35e50176d8`. Every selected input matches
the completed run. It includes raw process/HTTP/state evidence, input snapshots,
focused before/after tests, static checks and independent cleanup receipts.

Earlier immutable archives remain separate:

- Original source failures: `/Users/dwelch/.codex/reports/litellm-original-contract-failures-20261114`, MANIFEST `7eb74e0076c5e2731c9c6cb5a7c6869846fa32563813b431b54e92bc02074cc7`.
- Harness preflight failure: `/Users/dwelch/.codex/reports/litellm-harness-preflight-failure-20261114`, MANIFEST `dbd863822d1bc9b73b5eba9edbc75fdba916c63a7a8aa59343e5ffc9c4d1e017`.

Static inventory now records 5,179 source files, 247 registered owners,
22 individual reviews, 254 pending documented candidates and 0 stale reviews.
Registration remains distinct from proof of successful execution.

## Limits and further work

Qualification covers the two pinned versions, Linux amd64, root URL, PostgreSQL
16, one application worker and this authentication-error path. Broader versions,
TLS/reverse proxies, provider inference and data extraction remain unqualified.
The documented empty-key-table no-signal result remains a detector limitation:
affected deployments using only a master key can return Safe, which does not
establish patched status. Native unrelated-service/latency-injection coverage is
not claimed; uniformly slow negative timing is covered by controlled regressions.
The standing Druid, FreeSWITCH, Superset-owner and WordPress-admin path deferrals,
plus the earlier Mettle file-test timeout with unverified cause, remain open.
