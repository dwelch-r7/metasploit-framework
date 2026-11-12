# NetAlertX file collection lab

These profiles use genuine, digest-pinned `jokobsk/netalertx` Linux amd64 images
for 24.9.12 and 24.10.12. `vendor.json` records their source revisions and the
actual PHP/backend source hashes. The application source is unchanged.

The target runs the vendor's database migrations, notification-table initializer,
configuration importer and API generation once. It then serves the real PHP
application with its shipped NGINX template and FPM configuration. Worker counts
are bounded. Discovery plugins, scanning loops and cron are not started. The
backend's optional initial release check uses a refused loopback proxy, avoiding
its unbounded external request. The normal startup timestamp is generated before
initialization. This lab qualifies the file-collection web path, not NetAlertX's
network-discovery or notification delivery functions.

Protected profiles configure the ordinary web password setting and verify real
wrong/correct login behavior. Public profiles explicitly disable web protection.
The 24.10.12 patch adds an authentication guard to the logs endpoint; disabling
web protection still allows its ordinary file-reading behavior. A fixed version
number alone therefore does not prove endpoint refusal under every configuration.
Native HTTP controls check exact file bytes through the real logs endpoint,
including HTML metacharacters, spaces and a quoted filename. Empty and missing
files are independently distinguished from successful collection. Runtime source
hashes, initialized SQLite integrity/settings, processes and cgroup counters are
recorded before owning module calls and again afterward.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb netalertx_24_9_12_protected netalertx_24_9_12_public netalertx_24_10_12_protected netalertx_24_10_12_public
```

Each profile selects eight short cases: repeated anonymous checks, normal
AutoCheck, forced collection, disabled AutoCheck, zero traversal depth, a path
with spaces, a quoted path, and missing/empty files. Actual loot bytes and SQL
host/vulnerability/CVE records are checked. The protected maintenance endpoint's
redirect is a separate check result from the logs endpoint's exposure. Tests do
not assume that failed detection proves a patched target.

Only three containers run at a time: target **192 MiB / 0.3 CPU / 64 tasks**,
Framework **640 MiB / 1 CPU / 256 tasks**, PostgreSQL **128 MiB / 0.2 CPU /
64 tasks**. Memory and swap limits match. Target state is temporary and no
persistent or anonymous volume is required. Only random loopback HTTP is
published. The runner removes its containers and temporary network after each
profile. Use the guarded runner to retain resource and cleanup evidence.

Sources:

- [Affected image source](https://github.com/netalertx/NetAlertX/tree/dcc43d1f3c6611cf1900c4d2d7aae0c5ec077ab4)
- [Control image source](https://github.com/netalertx/NetAlertX/tree/d36486ef6de3985dac19195cf333e4de31601bcb)
- [Control endpoint authentication guard](https://github.com/netalertx/NetAlertX/blob/d36486ef6de3985dac19195cf333e4de31601bcb/front/php/components/logs.php)
- [Module guide](../../../documentation/modules/auxiliary/scanner/http/netalertx_file_read.md)

These fixtures use only dummy local credentials and controlled files. Other
releases, architectures, mounted application paths and backend services need
separate validation. Human-written module Scenarios remain unchanged.
