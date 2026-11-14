# HugeGraph container qualification — 2026-11-14

The genuine HugeGraph matrix passes **34 functional examples and 90 public
module calls**, with **12 exact command proofs, six deliberate launch failures,
18 complete session lifecycles and 12 fetch-file removals while sessions remain
live**. This adds one qualified owner and four profiles: the campaign reaches
**232 modules qualified in covered paths, 273 profiles and 2,630 functional
examples**. The broader campaign remains incomplete. No PR is created.

## Reproduction and scope

From the Framework root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb hugegraph hugegraph_prefix hugegraph_open_130 hugegraph_auth_130
```

| Family | Genuine application | Configuration | Examples | Public calls | Complete sessions |
| --- | --- | --- | ---: | ---: | ---: |
| `hugegraph` | 1.0.0 | RocksDB, no authentication | 9 | 22 | 6 |
| `hugegraph_prefix` | 1.2.0 | Memory backend, real `/hugegraph/` context | 9 | 22 | 6 |
| `hugegraph_open_130` | 1.3.0 | Memory backend, no authentication | 9 | 22 | 6 |
| `hugegraph_auth_130` | 1.3.0 | Memory backend, ConfigAuthenticator, auth graph factory | 7 | 24 | 0 |

All images are upstream Linux amd64 images pinned by manifest digest in
[vendor.json](hugegraph/vendor.json). Each runs its real Java 11.0.16 server,
Gremlin engine and unchanged vendor JARs. No replacement HTTP endpoint or owner
is used. Configuration and the supported standalone RPC setting are explained
in the [lab guide](hugegraph/README.md).

Run `20261114T020159-fe856b` took approximately 15 minutes 26 seconds, including
build/setup, a cold console, four serial configurations and cleanup. Individual
families can be selected for a shorter focused run. The three exploitable
profiles exercise Bash, fetched Linux shell and fetched Linux Meterpreter twice
each, with AutoCheck enabled and disabled. Public session APIs prove remote
identity, exact file bytes and process identity; database rows must transition
from open to closed after graceful remote shutdown. Fetch executables disappear
while their sessions remain usable. No session/job is left for the next case.

## Findings and fixes

The unchanged owner successfully executed an exact command, but retained the
renamed worker: JVM thread `#62` changed from `gremlin-server-exec-1` to `AiuzJy`
and remained alive. The native bypass restores its worker in `finally`, so this
was an owner defect. The source now restores the original name in `finally`.
Tests compare worker identities/names after successful calls, while sessions
are live, and after real launch failures. For the latter, the lab temporarily
removes Bash execute permission, observes HTTP 500, and restores the original
mode and file hash before checking the sandbox again.

The original check ignored `TARGETURI`: a nonexistent path incorrectly returned
`Appears` using the root banner. It now queries the configured context and
validates product identity and version types. Malformed documents return a
reason-bearing `Unknown` result. The genuine prefixed deployment passes.

HugeGraph's challenge uses `WWW-Authenticate: Missing authentication credentials`
without the Basic scheme. Correct Framework HTTP credentials originally received
401, while the native client succeeded with the same credentials in a preemptive
Basic header. The owner now sends configured Basic credentials on both requests.
Missing responses, access failures and unexpected Gremlin replies now raise
specific, concise module failures. Valid, wrong and absent credentials are
covered; the protected target accepts normal authenticated queries but rejects
the execution bypass, including with AutoCheck disabled.

**Version 1.3.0 alone is insufficient evidence of protection.** The unauthenticated
image remains exploitable. Apache's [advisory](https://openwall.com/lists/oss-security/2024/04/22/3)
requires Java 11 and authentication alongside the upgrade. The passive check
retains `Appears` for 1.3.0; it does not claim that execution is proven. In the
protected configuration, actual exploitation returns an explicit failure.

Source fix: `76b41ae7de00cfa70a8da503752a89f99e8d63f3`, cherry-picked from isolated
worker commit `d83bed66ca80db0941c9f76112c335d18def4efa`. The selected
fixture bytes are committed as `734e81fbec981cab3eb08eaf5bf732496df40f9f` and match all
60 tested input hashes.

## Independent verification and cleanup

All **238 native probe invocations** exit zero. Before/after controls match for
each profile: product/version, graph arithmetic, empty graph, vendor JAR hashes,
live JVM security-manager/heap flags, unchanged free-memory configuration,
ordinary sandbox rejection, and positive or blocked CVE execution. The protected
profile also rejects unauthenticated graph queries. Gzip headers, raw response
bytes and decoded bodies are retained.

Exactly three containers run at a time: target 1,024 MiB/one CPU, Framework
768 MiB/one CPU and PostgreSQL 128 MiB/0.2 CPU. Swap equals the memory cap;
privileged mode is disabled and published ports bind only to localhost. OOM,
OOM-kill and PID-limit counters remain zero. Each vendor image creates one
anonymous application volume. All **36 independent final cleanup queries** pass
for the twelve container IDs, four networks and four volumes, including project
and global inventory checks. Five subsequent inventories are empty, both locks
are free, and the temporary container guard terminates with actual exit zero.

The functional manager exits **0**. Its original private observation helper
raced Compose preflight and exited **1**, making the enclosing private launcher
exit 1. This is preserved as an observation failure, separate from the passing
module suite. A bounded recovery observer exits **0**: it independently validates
the first profile's saved live Docker inspection and actual cold BOOT/prompt and
fresh cache, then directly observes the other three profiles and their normal
same-invocation metadata seeds. The first observation is explicitly labelled
post-run; it is not presented as a direct live observation.

Focused source specs: original **38 examples/20 failures**, candidate
**38 examples/zero failures**, actual exits 1 and 0. Strict Ruby lint and msftidy
retain exactly two original source offenses: duplicate RPORT registration and
the documented HttpClient-only peer-prefix false positive. No new offenses;
both specs are clean. Module documentation tidy and syntax checks pass. The
original module guide's `## Scenarios` through EOF is byte-for-byte preserved
(SHA-256 `6f759c7222eda89d5665cda457a68177dbc301454fa10fc492ff5504dd2af7fe`).

## Evidence and earlier failures

The immutable archive is
`/Users/dwelch/.codex/reports/hugegraph-qualified-20261114`: **682 files, 60
selected inputs**, independent copies with verified hashes and no hardlinks.
Its `MANIFEST.sha256` hash is
`09fc6e4ee5956377d2ebae0ca5debda4147d8949240bd9e900c878fc0a381262`.

Separate immutable archives preserve the original owner failures:

- `hugegraph-owner-before-20261114`: actual command success, ignored context and
  retained worker name; manifest `a3fa08a0fb0f3282b7f1f1ab15ae1fe5cc09c8413fe2eea6dc0f39a87f6e9623`.
- `hugegraph-auth-owner-before-20261114`: actual credential-negotiation failure;
  manifest `cd899eaebd918a360f4c2703f3801d54665b906c361d84db9aedffe95b952087`.
  One AutoCheck-disabled example failed in the Ruby harness before dispatch due
  to missing hash braces. It was corrected before the final run and is not
  described as an owner failure.

Native calibration archives separately retain insufficient heap/free memory,
REST-before-Gremlin readiness, the initial gzip decoder assumption,
ConfigAuthenticator's unsupported AuthManager RPC service, and an overly narrow
403-only sandbox oracle. The authenticated vendor filter actually returns 400.
The final native authenticated calibration archive is
`hugegraph-native-auth-qualified-20261114`, manifest
`85dcf08fafef89310e29c332765ef6d22f1b636ef89dffa9f3cd0c0fff737147`.
These setup/oracle failures were investigated before drawing module verdicts.

## Self-review and remaining scope

**Summary:** The four genuine configurations qualify the covered owner paths;
source, setup, oracle and observation failures have distinct evidence.

**What looks good:** Real sessions and command bytes, repeat execution,
exception-path restoration, authenticated negative controls, preserved Scenarios,
bounded resources and exact resource-removal audits.

**Concerns:** Other versions, architectures, distributed RPC,
StandardAuthenticator and other graph backends remain unverified. Existing
above-range version classifications have unit compatibility coverage, not new
target evidence. The two legacy lint offenses remain disclosed. No additional
material finding remains within the tested configurations.

**Suggestions:** Continue the inventory rather than infer feasibility or success
from documentation hints. Current inventory: 5,179 source files, 234 registered
owners, 271 pending documented container hints and zero stale reviews.
`druid_js`, `freeswitch_batch`, `superset_rce_owner` and `wordpress_admin` retain
their previously recorded deferrals. This checkpoint does not resolve the older
remote Mettle `post/test/file` timeout; its cause remains unverified.
