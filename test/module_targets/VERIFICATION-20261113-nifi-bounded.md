# Bounded NiFi discovery validation — 13 November 2026

## Summary

Current input-matched checkpoint: **224 qualified modules, 246 profiles and
2,350 functional examples**. The broader campaign remains active. No PR is
created.

The former six-container discovery topology is split into three serial profiles.
All 15 original version/login/reporting cases remain present, without duplicate
or dropped case descriptions. The fresh replay passes all 15 cases with 31
public module calls and no pending examples or errors outside examples. No
production module or library is changed.

## What looks good

Run the complete matrix with the [target guide](nifi_discovery/README.md):

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/nifi_discovery/run.rb
```

| Family | Genuine release/mode | Cases | Public calls | Containers |
| --- | --- | ---: | ---: | ---: |
| `nifi_discovery` | 1.13.2, ordinary HTTP without logins | 5 | 10 | 4 |
| `nifi_discovery_vulnerable` | 1.21.0, single-user HTTPS | 6 | 13 | 3 |
| `nifi_discovery_fixed` | 1.22.0, single-user HTTPS | 4 | 8 | 3 |

The original family now runs only the legacy cases; use the launcher for the
whole matrix. Release labels refer to the separate H2 issue, not to a claim
that the discovery scanners exploit it. Images remain official and pinned by
digest. No application response, authentication endpoint or module result is
simulated.

Each profile runs one NiFi service, Framework and reporting PostgreSQL. Legacy
also runs genuine unrelated Apache HTTP. NiFi is capped at two CPUs, 1,536 MiB
with no extra swap and 512 tasks. Total caps are 2,560 MiB/3.9 CPUs/960 tasks
for legacy and 2,432 MiB/3.7 CPUs/832 tasks for HTTPS. Application ports publish
only on loopback, and the guarded launcher serializes projects.

Six independent native phases verify actual UI/API versions, login support,
accepted/rejected credentials, authenticated identity, missing-path behavior,
UID and Java. Flow component IDs and the properties-file hash are identical
before and after testing. The selected-release probe reuses the existing native
client, script parser and version catalog; the shared NiFi helper and seven
other profile manifests remain byte-exact. Complete module guides, including
human Scenarios, are unchanged.

Ordinary module cases run twice. Positive authentication verifies exact
credential/service/origin/workspace joins, successful status and attempt time.
Duplicates are refused, two workspaces remain isolated, and negative cases leave
no credentials. The branded HTTP 200 error page and unrelated Apache content
remain genuine negative controls. First console startup is independently
observed cold with two fresh metadata files; later profiles reuse only the same
invocation's verified cache.

Every role's complete memory/PID counters are captured before assertions. All
OOM, OOM-kill and PID-limit counters are zero. NiFi memory-boundary counts are
8,611 / 3,359 / 3,422; the other roles record zero. These boundary events are
reported separately from OOM events, following the [kernel definitions](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files).
No memory cap or functional assertion was relaxed to obtain the replay.

Final run `20261113T144525-31604a`, tested revision
`30ec88f666d250b66fc28f3161e690216df1566c`, completes naturally in approximately
6 minutes 35 seconds including startup. Manager, observer and controller exit 0;
all three process IDs are absent. Forty-six independent cleanup queries verify
all 10 containers, three networks and 21 anonymous image volumes absent, plus an
empty global container inventory. The guard retires with exit 0, its PID absent
and both advisory locks free.

## Concerns

The first frozen run passes all 15 functional cases and both native phases for
every release, but remains unqualified because the new after-hook incorrectly
requires zero memory-boundary events. Its first failed assertion also prevents
collecting the other roles' counters. That run is sealed before correction.
The corrected fixture records all counters, distinguishes boundary events from
OOM failures, and retains strict OOM/PID checks. The full matrix is then replayed
at identical caps. This is a fixture-oracle correction, not a module defect or
a retry-until-green result.

The discovery profiles qualify these three releases and ordinary HTTP/single-user
HTTPS modes. Windows, IPv6, LDAP/OIDC/client-certificate authentication, every
brute-force option and trusted-certificate behavior remain outside this lab.
Processor execution, H2 execution and credential gathering retain their separate
qualification; these discovery tests do not replace those labs.

MySQL capture still needs bounded revalidation at the changed shared-library
hash. The previously confirmed concurrent FreeSWITCH credential-library insert
race remains excluded. Earlier Druid JavaScript, Superset owner-RCE and WordPress
admin exclusions are unchanged. The inventory still has 277 pending documented
container hints and no stale reviews; the overall goal is incomplete.

## Suggestions

Split the MySQL capture matrix without dropping genuine client/server pairs.
Check the old native seed predicate before claiming literal-zero-byte challenge
coverage: membership of hexadecimal digit `0` does not prove byte `00` occurs.
Then continue valuable feasible modules and the companion FreeSWITCH execution
families. Keep the dependency concurrency investigation separate.

## Verification receipts

Syntax, strict changed-Ruby lint and diff checks pass. Original discovery is
explicitly selected with the acceptance tag; an initial dry-run selected seven
unrelated helper examples and is retained as an invalid discovery attempt.
The corrected original catalog contains 15 cases; selected catalogs partition
exactly 5/6/4. A Compose preflight observer's decimal-string/integer comparison
is corrected before runtime; the actual caps do not change.

The first run `20261113T143322-65b5f8` is sealed with 261 entries and 66 pinned
inputs, manifest
`85f7c2f16f84e4cd1a0e605dbe207d985110eebb18f192a6a9c1331677a3cc83`.
The final run is sealed with 276 entries and 66 pinned inputs, manifest
`9be70b6d9e9d06787ccce1e8b704d55a12f9cf1ff7fb9f9a716fb5e61b3fb284`.
Every sealed entry is independently verified, read-only and single-linked.
