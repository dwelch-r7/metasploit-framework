# Solr backup/restore delivery

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb solr_backup
```

The twelve-case profile exercises the version scanner and
`exploit/linux/http/apache_solr_backup_restore` on genuine Solr 9.0.0, with
anonymous and Basic-authenticated access, and Solr 9.4.1 as a negative target.
It covers check results, fresh command execution, fetched Linux x64 Meterpreter,
wrong/absent credentials, a valid denied role, missing paths and unrelated HTTP.
Each positive execution repeats and proves execution as the real `solr` user.

The official Solr images and separate JDK 17 compiler are digest-pinned. The
native producer compiles the readable [Java initializer](SourceParser.java),
copies the actual vendor configset and drives real upload/create/backup APIs.
It compares both exported class-file hashes to the actual compiler output,
triggers a fresh target-side marker, and restores the original collection,
configset and directory inventories. The compiler is a target-only dependency;
Framework's dependencies and shared runner are unchanged.

Solr 9.4.1 accepts the ZIP with HTTP 200 but filters the executable class. Native
controls verify its absence in ZooKeeper and both exported backups, then prove
the final class load fails without creating the marker. HTTP 200/400 and the
module's success banner are never execution oracles. The selected 9.0.0 image
uses Java 17, matching the owning module's embedded class-file requirement.

The native investigation also found class filtering on 9.4.0 defaults, including
with authenticated upload. That delivery configuration remains unqualified;
this profile does not claim every release in the advisory range works with the
module's class-upload technique. See the [vendor advisory](https://solr.apache.org/security-news.html#2024-02-08-cve-2023-50386-apache-solr-backup-restore-apis-allow-for-deployment-of-executables-in-malicious-configsets).

Module cleanup must remove its registered collections/configsets. Documented
backup files and failed-core directories are captured before explicit operator
removal. Tests require the original API and directory inventories before each
repeat, real session command proof, and closure of callback/stager listeners.
Each run owns the last reference to its Fetch HTTP service: tests require an
empty service registry, no actual Linux LISTEN socket, and connection refusal
from the previous fetch URL after cleanup. Component tests separately retain
another concurrent owner's working resource and prove 404 for a removed route
while that other owner remains. The original retained-pool observations remain
in the earlier immutable evidence; they are not treated as per-run closure.
The exact configured `FETCH_DELETE` path must become absent through
bounded polling before file inventory/capture; other copy failures remain fatal.
Native
CLI/HTTP controls independently establish authentication and permission policy;
SQL queries verify reported services and accepted credentials.

See the [shared Solr guide](../solr_velocity/README.md) for isolation, artifact
provenance and coverage limits. Other Java/Solr versions, CPU architectures,
custom repository layouts, TLS and external services remain unqualified. No
human Scenarios are generated or replaced.
