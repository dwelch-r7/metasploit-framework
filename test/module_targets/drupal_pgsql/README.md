# Drupal PostgreSQL EntityQuery target

This lab exercises the public `check` and `run` entrypoints of
`auxiliary/scanner/http/drupal_pgsql_entityquery_sqli`. The scanner supplies console `check` through
`Msf::Auxiliary::MultipleTargetHosts#check`, which calls the real `check_host`.
No request, SQLi implementation, clock or reporting API is stubbed.

Official complete Drupal 11.2.0 and 11.2.12 archives include their own `vendor/`
dependencies. `releases.json` pins each archive and the relevant Core sources.
The pinned official Drupal image supplies PHP 8.4.8 and Apache; startup extracts
one full release into a fresh directory rather than overlaying another release.
Core's noninteractive installer, module installer and entity APIs create the
standard site, JSON:API and published article. No Composer or Drush installation
is required. The application uses an ordinary PostgreSQL role that owns only
its target database. A separate ordinary role/database holds Framework reports
in the same PostgreSQL container.

The [Core advisory](https://www.drupal.org/sa-core-2026-004) describes the affected
PostgreSQL release branches. These profiles cover one affected/fixed pair;
results must not be extrapolated to every listed release or database backend.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/drupal_pgsql/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb drupal_pgsql
```

Run the profiles serially using the guarded launcher. PostgreSQL profiles have two
containers: application at 0.5 CPU/768 MiB and PostgreSQL at 0.5 CPU/512 MiB;
the unrelated Apache application uses 0.25 CPU/128 MiB. The MariaDB profile
adds one 0.5 CPU/512 MiB MariaDB container, for three total; PostgreSQL then
serves only Framework reports. Swap equals memory,
PID limits are 128, and published HTTP/database ports bind only to loopback.
The launcher records source digests, console/RSpec output and cleanup. Native
controls record real HTTP bodies, timings, source versions, schema settings,
application state, actual database reports and cgroup counters before/after.
Each normal case runs `run` followed by `check`, twice in the same workspace,
to verify both entrypoints, reuse and report deduplication. A separate case
runs two fresh checks without a preceding run. Sessions/jobs and loot must remain empty.

| Profile | State | Functional cases |
| --- | --- | ---: |
| `drupal_pgsql` | 11.2.0; published article; default/custom/case-sensitive fields, fractional delay and invalid prerequisites | 11 |
| `drupal_pgsql_fixed` | 11.2.12; same real article and field configuration | 3 |
| `drupal_pgsql_mariadb` | 11.2.0 with genuine MariaDB 11.2.2; unaffected backend | 3 |
| `drupal_pgsql_prefix` | 11.2.0 served under `/lab/` | 3 |
| `drupal_pgsql_empty` | 11.2.0 with no articles | 1 |
| `drupal_pgsql_disabled` | 11.2.0 with JSON:API disabled | 1 |
| `drupal_pgsql_private` | 11.2.0 with anonymous content access revoked | 1 |
| `drupal_pgsql_unrelated` | Real unrelated Apache site | 1 |

Before module calls, normal JSON:API requests must return the real article UUID,
Unicode title, case-insensitive matches, case-sensitive misses and empty results.
Independent true/false PostgreSQL sleep requests establish the injection boundary.
Each timing request uses distinct filter values: Drupal's anonymous page cache
can otherwise serve an identical URL without executing SQL. The module's own
random filter markers remain enabled. Genuine inaccessible/empty deployment
states receive their own prerequisite checks and must not produce vulnerabilities.
Application users, nodes, fields and relevant installed sources must remain
unchanged. The human-written module guide and Scenarios are left intact.

These are disposable vulnerable fixtures with public demonstration credentials
(`module_admin` / `module-target-password`). Keep the loopback bindings. Download
or setup failures are target failures until independently investigated; a passing
healthcheck alone does not establish module behavior.
