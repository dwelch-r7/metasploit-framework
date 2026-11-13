# Bounded database capture validation — 13 November 2026

## Summary

Current input-matched checkpoint: **225 qualified modules, 250 profiles and
2,392 functional examples**. The broader campaign remains active. No PR is
created.

Four serial MySQL client/server pairings replace the oversized capture topology.
The fresh replay passes all 42 MySQL cases and the 12-case shared MSSQL
regression: 54 examples, zero failures, pending examples or errors outside
examples. No production module or library changes.

## What looks good

Run the complete matrix with the [target guide](capture_mysql/README.md):

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/capture_mysql/run.rb
```

| Family | Genuine client / native database | Cases | Public runs | Containers |
| --- | --- | ---: | ---: | ---: |
| `capture_mysql` | Oracle 8.0.36 / MySQL 8.0.36 | 13 | 25 | 5 |
| `capture_mysql_oracle_mariadb` | Oracle 8.0.36 / MariaDB 11.2.2 | 13 | 25 | 5 |
| `capture_mysql_mariadb_mysql` | MariaDB 11.2.2 / MySQL 8.0.36 | 8 | 15 | 5 |
| `capture_mysql_mariadb_mariadb` | MariaDB 11.2.2 / MariaDB 11.2.2 | 8 | 15 | 5 |
| `capture_mssql` | FreeTDS / SQL Server 2019 | 12 | 23 | 4 |

All original 17 MySQL case descriptions remain, with one accurately renamed
native-seed case and two new literal-NUL challenge cases. The selected client
catalogs partition the client-specific cases and repeat the two common cases.
Both native server implementations remain covered by both genuine clients.
The original MSSQL catalog is unchanged. The original `capture_mysql` family
now runs one pairing; use the launcher for the full matrix.

Each MySQL profile caps total RAM at 2,304 MiB, CPU at 3.4 and tasks at 832.
The native database has 1,024 MiB/one CPU/256 tasks; Framework
768 MiB/1.5 CPUs/256 tasks; packet monitor 192 MiB/0.4 CPU/128 tasks;
client 192 MiB/0.3 CPU/128 tasks; reporting PostgreSQL
128 MiB/0.2 CPU/64 tasks. MSSQL retains its 3 GiB server limit, adds two
CPUs/512 tasks, and uses the same other-role caps: 4,160 MiB/4.1 CPUs/960 tasks
total. RAM and combined RAM/swap limits are equal. No host ports are published.
The image-only build dependency is never started. The unchanged guard refuses
more than five runtime containers and serializes startup through teardown.
An independent live observer verifies every actual role and cap.

Eight MySQL native phases run before and after Framework testing. Four real
accounts cover ordinary, empty and binary-response boundary cases; wrong
passwords are rejected. Actual SQL identity/version, plugin negotiation,
client TLS behavior and independently calculated native-password responses
are checked against PCAP bytes. After-controls do not reseed accounts, and
account-state hashes remain identical. MSSQL retains its independent native
preflight. In total, nine native phases issue 106 commands and retain 65 PCAPs.

The 103 public module runs include malformed-input refusals. Ordinary listener
cases restart and repeat; 98 genuine-client PCAPs establish actual owning
traffic. Direct reporting SQL verifies exact credentials, private types,
service/origin/workspace joins and Untried status. John output preserves exact
challenge/response bytes. Empty authentication and greeting-only requests
create no credentials; malformed input leaves no listener; changing the console
workspace does not move a listener's captures. First console startup is observed
cold with two fresh metadata files; later profiles reuse only the same
invocation's verified cache.

All five roles in every MySQL profile record complete memory/PID counters.
Every memory-boundary, OOM, OOM-kill and PID-limit count is zero. MSSQL has live
cap and final inspection checks; its spec does not add a cgroup counter gate.
Complete MySQL module documentation, including human Scenarios, and both
production capture modules remain byte-exact.

Run `20261113T151645-5792c5`, revision
`311228e8499e0d682d8dcd826a92397409357566`, completes naturally in approximately
14 minutes 19 seconds including startup. Manager, observer and controller exit
0, with all process IDs absent. Forty-nine independent cleanup queries prove
all 24 containers, five networks and four anonymous volumes absent, plus an
empty global container inventory. The guard exits 0, its PID is absent and
both advisory locks are free.

## Concerns

The historical native-seed predicate tested hexadecimal digit `0`, not byte
`00`. Its captured seed `101057436d7d1f5730797550571d1d542c2d253c` contains no
NUL byte. The new probe records actual NUL membership without requiring random
native seeds to contain one. Separate deterministic configured-NUL cases pass
with both genuine clients against both native baselines, twice per case.
This corrects a fixture coverage claim; no fresh module defect is identified.

Qualification covers these pinned releases and the documented native-password,
TDS/NTLM capture paths. It does not establish all database releases, other
MySQL authentication plugins or encrypted credential capture. The previously
confirmed concurrent FreeSWITCH credential-library insert race remains excluded.
Earlier Druid JavaScript, Superset owner-RCE and WordPress admin exclusions
remain unchanged. The inventory has 5,179 source files, 227 registered sources,
277 pending documented container hints and zero stale reviews; the goal is
incomplete.

## Suggestions

Continue valuable feasible modules, including those without documentation hints.
The companion FreeSWITCH execution module has a source-only plan for native
command/session and available payload delivery paths; the concurrency dependency
investigation remains separate. Preserve the serial resource limit and require
independent controls before attributing a failed test to a module.

## Verification receipts

Ruby syntax, strict changed-Ruby lint, Python AST, exact case-catalog partition,
merged Compose configuration and diff checks pass. The original catalog commands
both exit 0; their initial private postprocessor fails because it assumes a
nonexistent MSSQL module document. That bookkeeping error is recorded separately
from functional execution and corrected before runtime.

The complete run is sealed at
`/Users/dwelch/.codex/reports/mysql-bounded-capture-qualified-20261113` with
1,100 entries and 71 pinned inputs, manifest
`c6b4262244e35e271f39540bad063e19577908f8153b50ff168ce9e5bdce051c`.
Every sealed entry is verified, read-only and single-linked. Historical native
seed evidence and the exact input-matched checkpoint are retained privately.
