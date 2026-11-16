# LearnPress SQL injection targets

These targets use genuine official LearnPress **4.2.7 / 4.2.7.1**, pinned
WordPress 6.8.3 / PHP 8.3.28, MariaDB 11.2.2, and an ordinary Framework reporting
role in PostgreSQL 16. The [original researcher](https://abrahack.com/posts/learnpress-sqli/)
and [vendor tag comparison](https://plugins.trac.wordpress.org/changeset?new_path=/learnpress/tags/4.2.7.1&old_path=/learnpress/tags/4.2.7)
describe the two affected APIs and the fix. `releases.json` pins exact official
archive and installed critical-file SHA256 values. The entire human module
guide and its Scenarios are preserved.

Prepare the ignored source cache with Docker available and no existing containers:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/learnpress_fields/prepare.rb
```

The guarded runner executes selected profiles serially, cleaning the previous
stack before starting the next. It refuses existing containers and holds the
shared user-scoped lock; it does not delete other work's containers.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb learnpress_fields_fixed learnpress_fields_inactive learnpress_fields_absent learnpress_fields_cached learnpress_fields_prefix learnpress_fields_subdirectory learnpress_fields_count2 learnpress_fields_c_fields learnpress_fields
```

| Profile | Native state | Public run coverage |
|---|---|---|
| `learnpress_fields` | Active 4.2.7, four genuine Core users, one published course | CVE-2024-8522, default COUNT=1, repeated |
| `learnpress_fields_c_fields` | Same genuine application | CVE-2024-8529, default COUNT=1, repeated |
| `learnpress_fields_cached` | Real JWT API cache populated across the original 100-value nonce pool | CVE-2024-8522 complete extraction despite cached timing inputs |
| `learnpress_fields_subdirectory` | Active 4.2.7 under `/wordpress` | Both actions with TARGETURI |
| `learnpress_fields_prefix` | Current `wp_native_users` and real `wp_users` backup in another owned DB | CVE-2024-8529 and current-site prefix detection |
| `learnpress_fields_count2` | Active 4.2.7 | CVE-2024-8522, explicit COUNT=2 |
| `learnpress_fields_fixed` | Active 4.2.7.1, real course and users | Both actions reject extraction |
| `learnpress_fields_inactive` | Installed 4.2.7, inactive, no fabricated course schema | Both actions reject extraction |
| `learnpress_fields_absent` | Genuine WordPress without LearnPress installed | Both actions reject extraction |

Installation uses native WordPress plugin activation, which creates LearnPress's
own tables and pages. A second fresh bootstrap loads the active plugin before
creating a published `lp_course` through Core APIs. No vendor source or HTTP
handler is patched. The cross-database backup copies actual Core schema and rows.
Inactive and absent states retain the genuine Core users and login application.

The module has two public actions and no check hook. Tests invoke public `run`
through a real isolated console with no HTTP, SQLi, credential or loot stubs.
Positive cases require entire native hashes, exact credential origin/service
context and exact loot lines. Repeated runs verify target-state reuse and
reporting deduplication. Negative cases require the module's rejection and no
credentials or loot.

Native controls inspect installed hashes, actual user/course state, application
and reporting roles, ordinary login/course HTTP, and independent true/false
SLEEP expressions before and after each profile. Their SQL literals differ
between actions and phases, so one control cannot consume another's cache key.
The JWT API caches normalized request params; an identical cached timing request
can return quickly even on the affected release. Cache priming uses 100 real
HTTP requests and three cached rechecks, without replacing module randomness.
A failed native control is a qualification/setup failure, not proof of correct
module rejection. Native snapshots cover selected source, user, course and
configuration state; they are not a full database dump.

The frontend API's vendor URL recognition requires a `/wp-json/lp/` URL fragment.
A bare query-string request can return a real `rest_no_route` even while the
module's frontend route is available. The fixtures retain working pretty
permalinks and test actual module paths. Other routing and SQL-mode combinations,
other releases, empty-course catalogues, COUNT=0/all-row extraction and noisy
networks remain unqualified.

Each stack has three capped containers: app 1 CPU / 512 MiB, MariaDB 0.5 CPU /
512 MiB, reporting PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory; PID limits
are 128 and init is enabled. Only loopback ports are published. Reporting reuses
the existing Elasticsearch component's ordinary-role PostgreSQL definition;
no Elasticsearch app starts. SqliDelay=0.6 keeps local time-blind extraction
bounded, but complete bcrypt hashes still take several minutes. A preliminary
0.4-second run saved two incorrect hash characters despite passing bracketing
native controls; its failed capture is retained. Apache access logs include
`duration_us` for each request to support timing investigations. The native
controls and cache priming retain their independent 0.8/0.4-second expressions.
The frontend action's observed true requests can take about 1.2 seconds at this
SQL delay. The repeated frontend and both-action subdirectory profiles therefore
declare `test_timeout: 1200`, allowing up to twenty minutes for their RSpec
command. Other profiles retain the runner's 600-second default. Complete
extraction still takes minutes; use a higher delay on noisy networks. The runner
removes all stack containers, attached volumes and
networks. Actual qualified results belong in the campaign verification journal.
