# Superset version and shared-runner verification — 2026-11-11

The checkpoint is **186 runtime modules, 128 qualified lab profiles and 1,447
functional examples**. This adds Superset 2.0.1 credential gathering and repeats
the fourteen-case 2.0.0 profile through the shared guarded runner. Both Superset
checks now recognize 2.0.1; the RCE module remains qualified only for its check,
with exploitation and sessions pending. The [earlier cookie checkpoint](VERIFICATION-20261111-superset.md)
retains the original signer/reporting repairs and historical selector limitation.

## Reproduce

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb superset_cookie superset_cookie_201
```

The [2.0.0](superset_cookie/README.md) and
[2.0.1](superset_cookie_201/README.md) profiles keep their Compose definitions,
initialization, native controls and acceptance tests in the repository. Each
uses four containers capped at 2,144 MiB and 2.15 CPUs. Profiles run serially;
the shared lock remains held through capture and teardown. Only the Apache
gateway publishes a random loopback port. Images and unrelated volumes remain.

## Native controls and original failure

An independent native-only 2.0.1 run (`f69f9a`) passed before owner execution.
The pinned vendor image reports Superset 2.0.1 with Flask 2.0.3, Flask-Login
0.4.1, Flask-AppBuilder 4.1.3, itsdangerous 2.1.1, SQLAlchemy 1.3.24 and Werkzeug
2.0.3. Installed sources, user roles, metadata and configuration are verified.
The native Flask serializer uses the observed `user_id` key. Both authenticated
and anonymous cookies can be elevated with the configured default key, a fresh
HTTP request identifies the administrator, and exact datasource secrets are
readable. Invalid signatures and invalid passwords are refused as expected.
An ordinary PostgreSQL login/query proves the datasource independently.

Unchanged-owner run `20261111T050406-79c43c` naturally exited one: four examples,
three failures, no pending or outside-example errors (123.438367 seconds).
Both owner checks incorrectly returned `Safe` for 2.0.1, so the gatherer's default
AutoCheck path aborted. Its explicit `ForceExploit` path collected real SQL
credential rows twice. Native-before and native-after passed with restored
selected logical state. This distinguishes an owner version defect from a
broken target or an assertion based only on printed success.

Both checks now retain their existing minimum and use `< 2.1.0` for the known
default-key condition. The vendor lists the default-key and datasource password
issues as affecting releases before 2.1.0; the separate SQLite/metadata-write RCE
issues have a later 2.1.1 boundary. These ranges do not establish RCE success on
a particular target. See the [official Superset advisories](https://superset.apache.org/admin-docs/security/cves/).
Twenty isolated whole-source check examples cover both owners, six version
boundaries and response failures; the unchanged baseline failed precisely the
two 2.0.1 expectations. These unit examples substitute HTTP boundaries and do
not prove native behavior on the other versions.

## Actual final batch

Run `20261111T052050-56149c`, source `e8b41696110a0a25fd0aa5cbed3ec7535d6e7072`,
naturally exited zero. The first invocation was refused before targets because
the Docker backend had stopped. The existing Docker application was restarted;
the same engine identity and empty inventory were verified before the actual
passing retry. This host interruption is not classified as a module failure.

| Profile | Actual examples | RSpec seconds | Result |
| --- | ---: | ---: | --- |
| Superset 2.0.0 | 14 | 147.304575 | Passed |
| Superset 2.0.1 | 4 | 89.810877 | Passed |

Both have zero failures, pending examples or outside-example errors. Each native
before phase records nine commands and sixteen HTTP requests, with a
separately captured PostgreSQL login/query; each after phase records eight commands and
sixteen HTTP requests. Selected logical accounts, datasource, dashboard and
key-value state return to their seed. Audit/login-history rows and SQLite file
bytes are deliberately outside that comparison.

The fourteen original cases retain genuine signer identity, exact reporting,
negative controls, workspace isolation and repeat behavior. The four new cases
require both checks to return `Appears`, successful credential gathering through
default AutoCheck, and stable connected SQL rows across two explicit forced
runs. No RCE exploit, payload or session was invoked.

Root observed the first returned console prompt, isolated BOOT, no first-profile
seed, and two fresh parsed atomic metadata snapshots (7,264 module entries and
two cache entries). The second profile reused those exact bytes through the
runner's normal cache path within the same invocation. Its returned BOOT was
isolated. The cache copier intentionally preserves source timestamps; an
initial audit assumption requiring fresh second timestamps was corrected from
that code and the four-way byte comparison. No metadata was manually seeded
or edited to satisfy the audit.

Live cgroups for the first profile showed four running roles below their caps
and no OOM events. Final inspect captures for both profiles confirm the exact
four-role limits, running state before teardown and no OOM kills. A second live
cgroup sample was not captured. Root independently verified 23 cleanup queries:
exact absence of eight container IDs, four network IDs and four owned volumes;
absence of both projects' resource labels; and an empty global container list.

All 129 original run files imported byte-for-byte; all 68 distinct selected
inputs match the primary worktree. The final 206-file local seal manifest is
`97a368e4a71b8208d24627a8d88b99c2b377269df079f8e1e8029304fc0935da`.
The 101-file native-only seal is
`a12c0e1b4d474d0a52fb1b03fb24f0e114ced175d2ffe9036fad6e131069ebe9`;
the 126-file original owner-failure seal is
`6b648827c0bc0ea370344ac00c3ca818bdf57c7a6265e3d043c72414a5121188`.
Original revisions, result maps, paths and commands remain unchanged.

## Shared runner review

The opt-in `module_endpoint_network: default` selects the gateway's internal
network only after actual project, service, container, network ownership and
IPv4 checks. Framework must share that internal network and remain isolated.
Other families keep the original single-network behavior. The endpoint helper
is required and fingerprinted only for opt-in families. Invalid manifests fail
before owner execution. Native/runtime limits, locks and cleanup are unchanged.

Root independently passed 53 focused infrastructure examples (24 endpoint,
eight wiring and 21 guard), plus the twenty version examples. The final primary run also loaded seven
existing datastore-formatting support examples: all eighty passed, with no
pending or outside-example errors (1.836206 seconds). The passing unit
runs block unexpected process execution. An earlier agent wiring attempt made
one failed read-only Docker inspect of a fake network identifier before its
boundary was tightened; it started or removed no targets. Source and unit seals
remain separate from the native/runtime evidence.

The seven other original runner methods are byte-identical. Root compared the
old and new default input algorithms on all 126 unchanged non-Superset base
manifests: selected paths and hashes match exactly. The standalone MinIO launcher
consumes only unchanged constructor/command/constants. This narrowly reviewed
runner compatibility preserves older qualification receipts and totals; it is
not a fresh replay of those historical targets. New opt-in Superset profiles
must have current runtime receipts. No original result hashes were rebound.

Changed Ruby syntax and non-owner lint pass. Both owners retain exactly the
28 baseline lint diagnostics; module tidy reproduces those existing diagnostics.
Module-document checks pass for RCE and retain the gatherer's pre-existing
leading-blank warning. Human Scenarios are byte-identical. No full suite ran.

**Summary:** Both profiles pass actual owner entry points with native controls;
2.0.1 false-safe checks and shared gateway selection are repaired.

**What looks good:** Actual HTTP identity, connected SQL graphs, repeat execution,
source provenance and exact independent teardown establish the tested behavior.

**Concerns:** Fixed/rotated-key profiles, HTTPS, other datasource backends,
unresolvable private DNS, and SQL Lab/permalink RCE sessions remain unqualified.
A resolvable service address is required to save a credential service/login.
The two broader deferred families remain unqualified; `--all` is not claimed to
pass. Full-suite and exact-head CI success are not inferred from focused tests.

**Suggestions:** Continue with native SQL Lab/permalink controls before adding
RCE owner calls, then fixed/rotated-key controls and the remaining inventory.
The goal remains active. No pull request was created.
