# Audiobookshelf verification — 12 November 2026

The checkpoint is **207 qualified modules, 180 profiles and 1,940 passing
functional examples**. The [new lab](audiobookshelf/README.md) adds four serial
profiles for `auxiliary/scanner/http/audiobookshelf_auth_bypass`. The campaign
remains incomplete: 294 documented container hints and unhinted candidates still
need review. Registration of 209 sources is not qualification. Existing
`druid_js`, `superset_rce_owner` and `wordpress_admin` profiles remain excluded.

## Genuine targets and results

Official 2.19.0 and 2.19.1 amd64 images are pinned by manifest/config digest in
[profiles.json](audiobookshelf/profiles.json). Relevant files match official
tagged source. Normal `tini -- node index.js` startup initializes the real
24-table SQLite database. Native requests create a root account and a protected
library using an empty local folder. No HTTP handler or module method is replaced.

All final examples use source `797875eaa3f3780e8652ad50909f23f6b4c0561d`.

| Target | Run | Examples | Failures | Spec seconds |
| --- | --- | ---: | ---: | ---: |
| Audiobookshelf 2.19.0 | `20261112T013911-f3dcd8` | 8 | 0 | 121.67 |
| Uninitialized 2.19.0 | `20261112T013911-f3dcd8` | 7 | 0 | 82.03 |
| Audiobookshelf 2.19.1 | `20261112T014808-03239b` | 8 | 0 | 117.78 |
| Apache 2.4.62 control | `20261112T014808-03239b` | 3 | 0 | 35.55 |

There are no pending examples or errors outside examples. The fixed/control
manager and its two live observers exit zero. The affected manager is terminal
with complete passing per-profile RSpec, native and cleanup receipts, but its
shell exit value was lost after a truncated tool observation. This missing
process receipt is retained explicitly; it is not represented as exit zero.
Both affected live observations contain passing console and resource evidence.

Each invocation's first console has an observed prompt, BOOT record and two
fresh metadata snapshots without a seeded cache. Its second console uses only
the observed normal seed from that invocation.

## Independent behavior and reporting

Native controls verify accepted/rejected root credentials, authenticated library
access, invalid-token rejection and real SQLite users/libraries. Separate
PostgreSQL credentials and native SQL verify the disposable Framework reporting
database. Its public schema is empty before Framework connects.

At both root and `/audiobookshelf` paths, the affected server rejects ordinary
and percent-encoded-query requests with 401. The literal bypass query returns
500 from synchronous API cache middleware; a separate nonexistent API route
changes from 401 to the application's ordinary 404. Fixed 2.19.1 rejects both
probes with 401. The generic production 500 body contains `Internal Server
Error`; the detailed stack appears in application logs. Health stays 200 and
the original Tini/Node process identities remain unchanged. The known
`/api/users` denial-of-service path is never invoked.

The uninitialized instance also rejects the ordinary API request with 401 and
exposes the bypass while retaining empty users/libraries. Module documentation
now recommends initialization for authenticated controls and protected data
without incorrectly calling it a scanner prerequisite. Human-written Options
and Scenarios remain byte-identical.

All **52 public module calls** cover `check` and `run`, repeated default and
prefixed paths, actual HTTP trace, genuine bearer headers, missing paths and a
refused port proved from the console's socket API. Trace captures preserve the
literal query slashes and real 500/401 differential. They also verify that
earlier authenticated headers do not leak into later default calls.

Actual Framework SQL verifies **11 services and 11 CVE records** with matching
host/port/service association and references. Ten records follow confirmed
bypasses. One affected authenticated baseline produces the scanner framework's
passive `Appears` record; subsequent `run` correctly reports authentication
enforcement and preserves that existing record without confirming a bypass.
The fixed release, unrelated service, missing paths and refused ports create no
service or vulnerability records. Repeats retain record IDs. All loot inventories
and loot rows remain empty.

Before/after controls preserve source hashes, protected SQLite projections,
authenticated library data, initialization state and process identity. Memory
and PID limit-event counters remain zero. No production module source change
was needed.

## Harness corrections and review

An earlier fixed/control run passes 11 examples on `a1f8a87`. Its evidence is
sealed separately before correcting a positive native assertion: the new
harness initially expected stack details in the production HTTP 500 body.
Native captures showed the generic body instead, before affected functional
tests ran. That assertion was corrected, then all four profiles were exercised
on the final source. This was a fixture expectation error, not a module defect.

An initial final-cleanup audit was started while the last control container was
still being removed. Its failed global-empty query is preserved separately.
After the manager exits, all **32 independent cleanup queries** pass, verifying
exact container/network removal, project inventories and an empty global
container list on the same engine/context. Two earlier native-only pilots have
six additional passing cleanup queries each; they do not qualify the module.

Changed Ruby RuboCop, Python syntax and whitespace checks pass. The module-doc
checker exits 1 solely for the pre-existing, unchanged universal `TARGETURI`
option heading. No new documentation finding was introduced.

**Summary:** Genuine affected/fixed and fresh-install scanner behavior passes.

**What looks good:** Native authentication, source, SQLite, process and HTTP
evidence agree with public module output, persisted records and exact teardown.

**Concerns:** Other affected releases, TLS/proxy configurations and alternate
authentication providers remain unqualified. Media playback is outside this
scanner's scope. The affected shell exit receipt is unavailable as disclosed
above. CI is assessed separately: at 01:48 UTC the prior published `5e7b28b`
has a [suite thread-count error](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43130588246/job/130893440990)
(18,251 examples, zero example failures, one after-suite error) and a
[Mettle file-move timeout](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43130588364/job/130893442652).
Their causes remain unverified; local acceptance does not establish green CI.

**Suggestions:** Continue remaining feasible modules serially, retaining native
controls and explicit separation of fixture, module and CI failures.

## Resources and evidence

Application profiles use three containers capped at **1,216 MiB/1.5 CPUs**:
target 320 MiB/0.3 CPU/96 tasks, reporting PostgreSQL 128 MiB/0.2 CPU/64 tasks
and Framework 768 MiB/1 CPU/256 tasks. Apache control totals 960 MiB/1.3 CPUs.
Live inspection verifies caps, equal memory/swap limits and loopback-only
published HTTP. Bounded tmpfs holds application and reporting state. There are
no named/anonymous data volumes, privileged containers or Docker socket mounts.

Each project is removed before the next runs. Docker disk pressure required
keeping one Audiobookshelf image cached at a time. Only recorded completed
task-owned images and 13 exact task-owned ownCloud build-cache records were
removed. That cache cleanup did not meaningfully restore available space;
serial image replacement did. No unrelated image or volume was pruned.

All **52 selected input hashes** are current. The read-only package
`audiobookshelf-verified-20261112` has **382 entries**; manifest SHA256:
`741b992c3691334fc7c14cd9a9808010aaefa96d58b30dbad1b9d817778d216d`.
The separate 240-entry original negative package has manifest
`038490ca124e23196d5cb551d2f4fe44e4ad959b6ba707bac5b19ffb186c0367`.
Independent files are rehashed and checked for read-only permissions and single
links before publication. Raw runs remain under `tmp/module-target-tests/`.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb audiobookshelf_2_19_1 audiobookshelf_unrelated
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb audiobookshelf_2_19_0 audiobookshelf_uninitialized
```

Publication is to the user's fork branch; no PR is created.
