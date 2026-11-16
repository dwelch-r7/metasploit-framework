# WP Fastest Cache SQL injection

These serial targets use official WordPress 6.8.3 / PHP 8.3.28, unmodified
WP Fastest Cache archives, MariaDB 11.2.2 and an ordinary Framework reporting
role in PostgreSQL 16. The affected/fixed source pair is **1.2.1 / 1.2.2**;
[the original research](https://wpscan.com/blog/unauthenticated-sql-injection-vulnerability-addressed-in-wp-fastest-cache-1-2-2/)
and the official archives identify 1.2.2 as fixed. `releases.json` pins archive
and installed critical-file hashes. `prepare.rb` reuses the shared official
WordPress archive preparer; no plugin download or source modification occurs
at container startup.

Run preparation with Docker available and no existing containers:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/wp_fastest_cache/prepare.rb
```

Then select one or more profiles. The guarded runner serializes them, removes
the preceding stack before starting the next, and refuses existing containers.
It does not remove containers belonging to other work.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wp_fastest_cache wp_fastest_cache_prefix_otherdb wp_fastest_cache_subdirectory wp_fastest_cache_count2 wp_fastest_cache_fixed wp_fastest_cache_excluded wp_fastest_cache_disabled wp_fastest_cache_inactive wp_fastest_cache_absent
```

| Profile | Native state | Public run coverage |
|---|---|---|
| `wp_fastest_cache` | Active 1.2.1, caching enabled, default prefix | Default COUNT=1; second execution |
| `wp_fastest_cache_prefix_otherdb` | Current `wp_native_users`, genuine `wp_users` backup in another owned database | Current-site prefix and complete hash |
| `wp_fastest_cache_subdirectory` | Active 1.2.1 under `/wordpress` | TARGETURI and complete hash |
| `wp_fastest_cache_count2` | Active 1.2.1 | Explicit COUNT=2 and two complete hashes |
| `wp_fastest_cache_fixed` | Active 1.2.2 with caching enabled | Repeated rejection, no credentials/loot |
| `wp_fastest_cache_excluded` | Active 1.2.1, logged-in-user exclusion enabled | Repeated rejection, no credentials/loot |
| `wp_fastest_cache_disabled` | Active 1.2.1, cache status property absent | Repeated rejection, no credentials/loot |
| `wp_fastest_cache_inactive` | Installed 1.2.1, inactive | Repeated rejection, no credentials/loot |
| `wp_fastest_cache_absent` | Genuine WordPress without the plugin installed | Repeated rejection, no credentials/loot |

The native installer uses WordPress account, plugin activation and option APIs.
Activation alone does not reach the vulnerable code: `wpFastestCacheStatus`
must be present. This vendor version checks property presence, so the disabled
profile omits that property. Enabling `wpFastestCacheLoggedInUser` returns before
the vulnerable admin-user query for a login cookie. No vendor source is patched
to obtain these states. All accounts and hashes come from genuine Core APIs;
the cross-database backup copies the actual Core table schema and four rows.

The module exposes `run_host` through Scanner and has no public check hook.
The tests exercise public `run` through a real isolated console, without HTTP,
SQLi, credential or loot stubs. Positive cases compare entire persisted hashes
and exact loot lines with native database rows; negatives require the module's
not-vulnerable result and empty reporting state. The default profile reruns to
verify per-execution state. Two-row extraction covers the COUNT override.

Each profile independently verifies ordinary login HTTP, true/false OR-cookie
sleep controls before and after module execution, source pins, native users,
plugin settings and unchanged database state. These controls use a different
SQL expression from the module's AND-cookie extraction. A failed timing or
native identity control is a setup/qualification failure, not evidence that
the module correctly rejected the target.

The low local SqliDelay of 0.4 seconds keeps genuine time-blind extraction
bounded. A single bcrypt hash still takes several minutes; the two-row profile
and default repeat may each take roughly six minutes. Use the module's normal
higher delay on noisy networks. This is bounded functional coverage, not every
WordPress, PHP, database, SQL mode or network configuration.

Each stack has exactly three containers: app (1 CPU / 384 MiB), MariaDB
(0.5 CPU / 512 MiB), and reporting PostgreSQL (0.25 CPU / 384 MiB). Every service
has a matching memory/swap cap, PID limit 128 and init. Only loopback ports are
published. The reporting service reuses the existing Elasticsearch component's
ordinary-role PostgreSQL definition; no Elasticsearch app is started. The
runner removes containers, attached volumes and networks on completion, and
artifacts record before/after OOM and PID events.

The existing human-authored module guide and Scenarios are preserved verbatim.
Actual qualification results and source-fix evidence belong in the campaign
verification journal; this setup guide defines reproducible expectations.
