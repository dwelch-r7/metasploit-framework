# Bounded MySQL capture native-client matrix

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/capture_mysql/run.rb
```

The launcher runs all four genuine Oracle/MariaDB client/server pairings serially,
then replays MSSQL because its functional spec shares the changed helpers.
No Framework capture-module behavior or database protocol is substituted.

| Family | Native client | Native database | Examples |
| --- | --- | --- | ---: |
| `capture_mysql` | Oracle 8.0.36 | MySQL 8.0.36 | 13 |
| `capture_mysql_oracle_mariadb` | Oracle 8.0.36 | MariaDB 11.2.2 | 13 |
| `capture_mysql_mariadb_mysql` | MariaDB 11.2.2 | MySQL 8.0.36 | 8 |
| `capture_mysql_mariadb_mariadb` | MariaDB 11.2.2 | MariaDB 11.2.2 | 8 |

Each pair runs five containers: packet monitor, native client, native database,
Framework and reporting PostgreSQL. Caps total 2,304 MiB, 3.4 CPUs and 832 tasks.
The database has 1,024 MiB/one CPU/256 tasks; Framework 768 MiB/1.5 CPUs/256 tasks;
the monitor 192 MiB/0.4 CPU/128 tasks; client 192 MiB/0.3 CPU/128 tasks; PostgreSQL
128 MiB/0.2 CPU/64 tasks. RAM and combined RAM/swap limits are equal. The
build-only base is an image dependency and is not started as a container. The
existing resource guard remains capped at five and inspects resolved services.

The MSSQL replay uses four containers, with its existing 3 GiB SQL Server
limit, two CPUs and 512 tasks. Its monitor, Framework and reporting database
have the same caps as above.

Native controls run before and after actual Framework jobs. Both phases validate
real accepted/denied accounts, empty passwords, plugin negotiation, native SQL
identity and actual packet responses. Account-state hashes must remain equal;
after-controls do not reseed accounts. Every listener case repeats and checks SQL,
John output, workspace ownership and actual listener/job cleanup.

The old native seed predicate checked for hex digit `0`, not byte `00`; its
captured seed contained no NUL byte. Native-seed/custom-version coverage remains,
with an accurate name. Separate configured challenges contain literal NUL bytes
and are verified through genuine client responses and independently decoded wire
bytes. Their qualification depends on real replay, not an assumed response.

All memory/PID counters are recorded. OOM/PID-limit events must remain zero;
memory-boundary counts are telemetry. No test dependency is added. See the
[database capture guide](../database_capture/README.md) for reporting semantics
and remaining protocol limits. Dated verification reports record actual results.
