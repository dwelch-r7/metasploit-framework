# Next.js middleware verification — 12 November 2026

The checkpoint is **209 qualified modules, 189 profiles and 2,038 passing
functional examples**. The [Next.js lab](nextjs_middleware/README.md) adds five
serial profiles for `auxiliary/scanner/http/nextjs_middleware_auth_bypass`.
Registration of 211 sources is not qualification; 292 documented
container hints and unhinted candidates remain. Existing `druid_js`,
`superset_rce_owner` and `wordpress_admin` profiles remain excluded.

## Genuine targets and final results

The source-built targets use genuine Next.js 15.2.2 and 15.2.3 production
servers, each with root or `src/` middleware. The unrelated target reuses the
existing real Apache 2.4.62 Basic-authenticated HTTP fixture. Next.js 15.2.3 fixes
this branch of CVE-2025-29927 according to the
[vendor advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw).

The official amd64 Node 22.23.5 base is pinned by manifest/config digest.
Version-specific package locks pin Next.js, React 19.0.0 and transitive packages
by registry integrity. Downloaded Next.js artifacts match their published
SHA512 values; four installed vendor files match those verified artifacts.
Normal `next build` and `next start` compile and serve the fixture. No Next.js
source, HTTP response or module method is replaced. The application legitimately
implements its authorization in middleware, with the normal `X-Powered-By`
banner disabled.

All final cases use source `554be139b30dbb6e1bb40f004d8bcfccaa8da73e`.

| Target | Run | Examples | Failures | Spec seconds |
| --- | --- | ---: | ---: | ---: |
| 15.2.2 root middleware | `20261112T045549-5c35c3` | 16 | 0 | 192.04 |
| 15.2.2 src middleware | `20261112T045549-5c35c3` | 16 | 0 | 143.28 |
| 15.2.3 root middleware | `20261112T045549-5c35c3` | 16 | 0 | 143.23 |
| 15.2.3 src middleware | `20261112T045549-5c35c3` | 16 | 0 | 144.89 |
| Apache 2.4.62 Basic auth | `20261112T045549-5c35c3` | 6 | 0 | 58.62 |

All 70 examples pass without pending examples or errors outside examples.
The original manager and observer coordinator exit zero; all five live profile
observations pass. The first console has an observed prompt, BOOT record and
two genuinely fresh metadata snapshots. Later consoles use only the normal
same-invocation seed, with matching bytes and hashes.

## Confirmed module defect and correction

An initial 56-case matrix passes on the original module. Additional protocol
rejection controls expose a real false positive: a 20,000-byte forced header
is rejected with HTTP 431 by Next.js and HTTP 400 by Apache, yet the scanner
claims an authorization bypass and persists a CVE record. Normal requests
remain authenticated, root health stays 200, and source/process/resource
controls pass. The request rejection does not expose protected content.

The matched seven-case diagnostic has **six failures originally and zero after
the fix**, with identical example IDs/order and seed 74117. The original creates
four false target CVE/service pairs on fixed Next.js and non-Next.js Apache,
plus two invalid confirmations on the genuinely affected server. A separate
affected 307-to-404 case passes both before and after: middleware was genuinely
skipped before routing reached a nonexistent downstream resource.

The narrow fix ignores HTTP errors except 404. It preserves successful
responses, redirect comparisons and that observed downstream-routing behavior.
Only the production module input changes between genuine diagnostic runs.
Target filesystem layers, runtime configuration, application/vendor files,
versions and build IDs stay identical. Image IDs differ because Compose adds
each invocation's project label; the initial overly strict image-ID comparison
and its correction are retained.

The separate source-fix worktree supplies 23 deterministic unit examples:
**12 original failures to zero fixed failures**, with identical spec bytes,
order and seed 49103. Real module initialization, URI handling, Rex responses
and check/run classification execute. Network, UI and reporting are explicit
doubles, and additional status/redirect boundaries are labeled synthetic.
The genuine target and SQL proof comes from the parent runs above.

## Public behavior and persisted reporting

All **130 public module calls** cover `check` and `run`, repeats, 307/302 login
redirects, 401/403 gates, both middleware names, forced correct/wrong/short
payloads, accepted/rejected cookies, public/missing paths, ordinary slash
normalization, parser rejection and a refused port independently proved from
the console's socket API. Cookie behavior is checked again without supplied
headers to detect leakage into later calls.

Native controls compare ordinary denials, valid and invalid cookies, exact
protected HTML/API content, crafted headers and both recursion names. They
also prove Apache Basic authentication remains enforced under all five default
payloads. Reporting PostgreSQL accepts/rejects its native credentials; its
public schema is empty before Framework connects. Across before/after phases,
284 independently recorded HTTP requests support these controls.

Actual SQL verifies **16 services and 16 CVE records**, with correct host, port,
service association and CVE reference. Repeats preserve record identities.
There are **14 confirmed public checks and 16 confirmed runs**. Four of those
calls confirm the genuine downstream 404 middleware skip; the other positive
calls reach protected resources with HTTP 200. Fixed targets, continuing gates,
protocol errors, unrelated authentication, public/missing paths and refused
ports produce no service or CVE records. Loot rows and files remain empty.

Before/after controls preserve vendor/application hashes, production build
identity, middleware manifests, process identity and ordinary page content.
The application remains healthy and its authentication remains enforced after
each parser error. Application memory and PID event counters stay zero.
Human-written module Scenarios remain byte-identical.

## Review and limits

**Summary:** Genuine affected/fixed behavior passes, and protocol errors no
longer create false vulnerability confirmations.

**What looks good:** Independent source, HTTP, credential, build/process and
SQL evidence agrees with public module behavior, repeated operation and exact
teardown. The final suite incorporates the discovered regression.

**Concerns:** Older affected Next.js branches, platform mitigations, TLS/proxy
deployments, other authentication providers, secondary authorization layers and
mid-response failures remain unqualified. The ordinary missing-path case is
ungated; the separately tested downstream-missing case is middleware-gated.
These observations do not establish all deployments or other CVEs are safe.

**Suggestions:** Continue remaining feasible modules serially and retain
explicit failure classification before treating an assertion as a module bug.

Strict RuboCop passes the three new/updated test files. Python syntax, whitespace
and declaration counts pass. Production-module RuboCop exits 1 and msftidy
exits 2 solely for five unchanged peer-prefix findings. The module-doc checker
retains one unchanged universal `TARGETURI` heading warning, shifted by the
added lab link. No unrelated lint sweep is included.

Separately, all four Ruby 3.3 jobs on previously published `b211a00` pass after
the [unit-fixture thread cleanup](VERIFICATION-20261112-thread-cleanup.md).
The [suite excluding content](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43150781107/job/130959155606)
reports 18,257 examples, zero failures and 33 pending examples; the
[content suite](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43150781107/job/130959155581)
reports 6,781 examples and zero failures. Neither log contains an outside-example
error. The same published head has a separate
[macOS Intel Mettle failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43150781384/job/130959157439):
46 examples, one failure in the reverse-HTTPS `post/test/cmd_exec`
special-character filename case (`minimal_uris_headers.profile`, seed 30806).
Its log reports malformed output with no process binary returned; the cause
remains unverified. The newly published head's CI is assessed separately.

## Resources and evidence

Profiles run serially with at most three containers. Application totals are
**1,216 MiB/1.5 CPUs**: Next.js 320 MiB/0.3 CPU/128 tasks, reporting PostgreSQL
128 MiB/0.2 CPU/64 tasks and Framework 768 MiB/1 CPU/256 tasks. Apache totals
960 MiB/1.3 CPUs. Live inspection verifies caps, equal memory/swap limits,
ordinary startup, loopback-only HTTP publication and no privileged/socket
access. Bounded tmpfs holds disposable database/cache state. There are no
named/anonymous data volumes.

All **40 independent final cleanup queries** pass on the same Docker engine
and context, including exact containers/networks, project inventories and an
empty global container list. Two native-only pilots add 14 cleanup queries;
each matched diagnostic run adds 24. Those preparatory runs do not add final
qualification examples. Only the exact completed Pi-hole image reference was
removed for disk space; no unrelated image or volume was pruned.

All **72 selected source hashes** are current. The final read-only,
single-link package `nextjs-middleware-verified-20261112` has 598 entries;
manifest SHA256:
`b4a0835afb4a7ab68348e1808f1caa87e7f9d27d6c65238af359d09809d25ca9`.

Separate immutable packages preserve the 56-case baseline (479 entries,
`14608eb2ab9b6c3abca3b4b287e065b916ad9a0561c43ed5713a6bee8bd99526`),
the original seven-case failure (343 entries,
`bf9e1175aabe23d02a9dfae0ff7d3ac6ac332476fb3ef618c4c0d8863564a4fb`)
and its corrected matched replay (403 entries,
`78ceb5502e3f6880a1e638d0e46b236dd3363e8e4e54e6de48b287ff5e2cc4b8`).
The worker's 43-entry unit package has manifest
`3773efff23243d9a831bd5fcae72b823d738d9dea37955f093ae01dc8b6be831`.
Every final entry is rehashed and checked for read-only permissions and single
links. Raw evidence remains under `tmp/module-target-tests/` and the lab README
provides the guarded reproduction command. Publication is to the user's fork;
no PR is created.
