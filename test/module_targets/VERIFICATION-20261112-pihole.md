# Pi-hole Top Domains verification — 12 November 2026

The checkpoint is **208 qualified modules, 184 profiles and 1,968 passing
functional examples**. The [Pi-hole lab](pihole_domains/README.md) adds four
serial profiles for `auxiliary/admin/http/pihole_domains_api_exec`. The campaign
remains incomplete: 293 documented container hints and unhinted candidates
still need review. Registration of 210 sources is not qualification. Existing
`druid_js`, `superset_rce_owner` and `wordpress_admin` profiles remain excluded.

## Genuine targets and results

Official amd64 Pi-hole images are pinned by manifest and image configuration
digest in [profiles.json](pihole_domains/profiles.json). Docker tag v5.5 contains
Core 5.2.4, **Web 5.3.1** and FTL 5.5. Docker 2021.09 contains Core 5.4,
**Web 5.6** and FTL 5.9. Docker tags are not web-component versions.

Normal `/s6-init` startup runs the vendor software. Six relevant application
files match official tagged source. Native setup establishes a real 11-table
SQLite gravity database and fetches a one-domain blocklist through local HTTP.
No application source, module method, response handler or banner is replaced.

All final examples use source `916456a1da134c8b5f17a2bbd1750dda502bc52f`.

| Target | Run | Examples | Failures | Spec seconds |
| --- | --- | ---: | ---: | ---: |
| Web 5.3.1, password protected | `20261112T030147-9f4445` | 8 | 0 | 313.18 |
| Web 5.3.1, passwordless | `20261112T030147-9f4445` | 8 | 0 | 269.13 |
| Web 5.6, fixed | `20261112T033515-0bed17` | 8 | 0 | 211.59 |
| Apache unrelated control | `20261112T033515-0bed17` | 4 | 0 | 41.59 |

There are no pending examples or errors outside examples. Both original
manager subprocesses and all four live observers exit zero. The fixed manager's
initial tool response was truncated; its original wrapper retained the actual
exit status, and its original PID was verified absent. No replacement run was
started to recover that observation.

Each invocation's first console has an observed prompt, BOOT record and two
fresh metadata snapshots without a supplied seed. The second console uses only
the normal seed produced by that same invocation.

## Verified module defect and correction

The old `<= 5.6` check incorrectly treats fixed Web 5.6 as vulnerable. Once the
fixture's real version metadata was initialized correctly, the original module
produced **five failures in eight fixed-target examples**, including two false
passive CVE records. Independent native injection rejection, source identities
and before/after state controls passed. The unrelated target passed all four
cases. This establishes a module defect independently of the fixture failures.

The [Web 5.5.1 hotfix](https://github.com/pi-hole/web/releases/tag/v5.5.1)
fixes the validation described in
[CVE-2021-32706](https://github.com/pi-hole/web/security/advisories/GHSA-5cm9-6p3m-v259).
The one-line correction uses `< 5.5.1`. Matched deterministic unit examples
cover Web 5.3.1, 5.5, 5.5.1, 5.6, 5.7 and absent version information: the original
has **6 examples / 2 failures**, and the fixed code has **6 / 0**, with identical
example order and seed 49103. Discovery and UI are explicitly doubled in that
unit comparison; genuine target coverage is provided by the table above.
The parent independently repeats the six fixed unit examples successfully.

## Independent behavior and reporting

Native HTTP controls verify accepted/rejected credentials on the protected
target, genuine passwordless behavior, CSRF handling, root command identity and
the PHP working directory. Separate PostgreSQL controls verify accepted/rejected
reporting credentials and an empty public schema before Framework connects.

All **46 public module calls** cover checks, runs, actual HTTP trace, invalid
commands, missing paths, refused ports and incorrect passwords. The refused
port is independently proved from the console's socket API. There are **nine
confirmed command executions** with output matching native `id` or `pwd`.
Two examples retain the first injected setting while executing a second,
different command. Passwordless operation legitimately ignores the supplied
incorrect password; the protected target rejects it.

Actual Framework SQL verifies **four services and four passive CVE records**,
with matching host, port, service association and CVE reference. These records
come from affected `Appears` checks, not confirmed exploitation. Subsequent
checks retain their IDs. Direct runs do not create vulnerability records under
the current module contract. Fixed targets, unrelated HTTP, missing paths and
refused ports create no records. Loot files and loot rows remain empty.

Before/after controls preserve source hashes, logical SQLite projections,
protected configuration, version-cache contents and initialization identity.
DNS remains healthy after normal gravity updates; the FTL process may restart
as part of that vendor operation. Memory and PID limit-event counters stay zero.

Successful module runs leave `API_EXCLUDE_DOMAINS` changed, as declared by the
module's configuration side effect. The harness verifies that mutation and
restores it natively after each case. This is fixture cleanup, not module
cleanup. Human-written module Scenarios remain unchanged.

## Fixture failures and review

Historical startup required signed archived Debian Buster metadata, writable
bounded APT storage and a lighttpd log directory owned by its actual user.
The native setup uses the real database's adlist configuration and a local
blocklist. It establishes valid API preferences before comparing fixed-target
rejection, which otherwise legitimately saves unrelated preferences.

Cold vendor metadata initially omitted the Web component and displayed the FTL
version in its place. Enabling the interface and invoking the vendor's local
update checker fixes that fixture prerequisite without fabricating a version
file. Older images can also return an incomplete HTTP 200 index page before
`gravity.db` exists; UI validation now follows real gravity initialization.
Native-only pilots, fixture-blocked calls and earlier passing results on
superseded helper revisions are retained separately and do not qualify this
checkpoint. All four final profiles were replayed after the last correction.

New Ruby tests/helpers pass strict RuboCop; syntax, whitespace and module-doc
checks pass. The changed production module retains four identical pre-existing
lint findings: duplicate `RPORT`, missing AutoCheck and two manual-peer-prefix
findings. The latter are false positives for this HttpClient-only module.
Production-module RuboCop exits 1 and msftidy exits 2 before and after the
one-line fix; this is not represented as clean lint.

**Summary:** A genuine false-positive version check is fixed and verified by
affected, fixed, passwordless and unrelated-service functional coverage.

**What looks good:** Native source, authentication, command, SQL, configuration,
DNS and HTTP evidence agree with public output and exact teardown.

**Concerns:** Other affected releases, full functional testing of Web 5.5.1,
TLS/proxies, alternate mount paths and mid-request failures remain unqualified.
The prior published Audiobookshelf head `043a4c9` has a
[Ruby 3.3 after-suite thread-count error](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43137573182/job/130916482743):
18,251 examples, zero example failures, but seven threads against six expected.
Local module acceptance does not establish green CI. A separate unit-fixture
cleanup fix is prepared in another worktree and is not part of this checkpoint.

**Suggestions:** Review and qualify that isolated CI fix, then continue remaining
feasible modules serially, retaining independent controls and failure records.

## Resources and evidence

Application profiles use three containers capped at **1,152 MiB/1.45 CPUs**;
the Apache control totals 960 MiB/1.3 CPUs. Live inspection verifies each memory,
CPU and PID cap, equal memory/swap limits, normal entrypoint and loopback-only
HTTP publication. Bounded tmpfs holds disposable state. No named/anonymous data
volumes, privileged containers, host DNS publication or Docker socket mounts
are used. Projects run serially and are removed before the next starts.

All **32 independent cleanup queries** pass on the same Docker engine/context,
including exact containers, networks, project inventories and an empty global
container inventory. Only recorded inactive task-owned image references were
removed to accommodate the Docker disk. No unrelated image or volume was pruned.

All **55 selected input hashes** are current. The read-only, single-link package
`pihole-verified-20261112` has **537 entries**; manifest SHA256:
`4731629562d38796e312ad89251d9f179aa599faf3ebe8ad1f4919b03f681b60`.
Separate original packages retain the fixture-blocked run (336 entries,
`ced74fbc32f9ad7aa68576a37cf62cd9e0513b8c7f52946c4dabb4d4401c65d5`)
and the genuine module failure (357 entries,
`5bf67f4a9d74d0b819d89b179a3269c76cbac0e81a5e48e50e61403ae7adc265`).
Raw runs remain under `tmp/module-target-tests/`; the lab README supplies the
two guarded reproduction commands. Publication is to the user's fork branch;
no PR is created.
