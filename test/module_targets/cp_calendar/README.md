# CP Multi-View Calendar SQL injection targets

These opt-in targets run unchanged CP Multi-View Calendar archives on pinned
WordPress 6.8.3 / PHP 8.3.28 and MariaDB 11.2.2, with an ordinary PostgreSQL 16
Framework reporting role. `releases.json` pins full archives and eight critical
installed files per release. The entire human module guide and Scenarios remain
unchanged. Qualification results belong in the campaign verification journal.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/cp_calendar/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb cp_calendar cp_calendar_event1 cp_calendar_subdirectory cp_calendar_prefix cp_calendar_115 cp_calendar_fixed cp_calendar_inactive cp_calendar_absent
```

The guarded runner holds the shared lock, refuses existing containers, and runs
profiles serially with complete teardown before the next stack. Preparation
only downloads and verifies ignored archives; it starts no target containers.

| Profile | Genuine application state | Public run coverage |
| --- | --- | --- |
| `cp_calendar` | Active 1.1.4, empty native event table | Repeat detection, plus a reserved closed loopback port |
| `cp_calendar_event1` | Active 1.1.4, event ID 1 created through its real vendor HTTP API | Repeat detection despite a real first event |
| `cp_calendar_subdirectory` | Active 1.1.4 under `/wordpress` | TARGETURI and repeat detection |
| `cp_calendar_prefix` | Active 1.1.4 with real `wp_native_` tables | Native prefix and repeat detection |
| `cp_calendar_115` | Pinned historical 1.1.5 archive | Repeat detection on these exact affected source bytes |
| `cp_calendar_fixed` | Official 1.3.70 | Repeated refusal |
| `cp_calendar_inactive` | Installed 1.1.4, not activated | Repeated refusal, no fabricated plugin schema |
| `cp_calendar_absent` | Genuine WordPress without the plugin | Repeated refusal |

The historical 1.1.4/1.1.5 official download URLs are unavailable. Their pinned
Git mirror commits are exported unchanged, then the archive wrapper is renamed
to the ordinary plugin directory. All eight selected files in each archive
match their original official SVN revisions 1076621/1101803 byte for byte.
The vendor installer creates its own four tables and default calendar. Standard
bulk activation avoids the later release's optional wizard redirect; no vendor
source, HTTP route or SQL schema is patched. A used-calendar fixture creates
its event through the genuine HTTP datafeed API, then snapshots native state.

The pinned 1.1.5 archive remains demonstrably SQL-injectable, despite a published
fix label. The 1.3.70 archive rejects the same well-formed SQL controls. This
qualifies the exact source pairs; it does not establish the earliest fixed
release or resolve possible historical tag changes.

The scanner has one public run path and no check hook. Real isolated console
calls require the expected finding and actual service-linked vulnerability
records, references and module-attempt context in an ordinary reporting role.
Repeat runs must deduplicate the finding. Negative cases must add no finding.
There are no HTTP, SQL, reporting or loot doubles in these functional tests.

Before and after each profile, native controls verify genuine login/editor
responses, independent true/false UNION markers with valid datetimes, installed
source, users, native schema/data and resource events. NULL injected dates can
abort PHP 8 rendering before the location field; selecting an existing event
can mask the UNION row. A native control failure does not prove correct module
refusal. Captured original failures remain separate from qualification counts.
Snapshots cover selected source/configuration/user/event state, not every table.

Each stack has at most three capped containers: app 1 CPU / 512 MiB, MariaDB
0.5 CPU / 512 MiB and reporting PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory,
PID limits are 128, init is enabled and ports bind only loopback. The reporting
service reuses the existing Elasticsearch PostgreSQL definition without starting
Elasticsearch. The runner removes all stack containers, volumes and networks.
Other WordPress/PHP/database releases, TLS/IPv6, authentication and different
calendar schemas remain unqualified. No PR is created by this campaign.
