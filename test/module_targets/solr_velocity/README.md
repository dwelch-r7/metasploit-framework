# Genuine Apache Solr targets

Run from the repository root with Docker Compose and Python 3 available:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb solr_velocity solr_velocity_sessions solr_backup
```

`solr_velocity` has ten check/discovery/command cases. The six-case
`solr_velocity_sessions` profile covers Java Meterpreter, Unix Bash and Linux
x64 curl-stager delivery, anonymously and with real Basic authentication. Each
command/session case repeats, executes a fresh target-side proof and verifies
the actual `solr` owner. The independent twelve-case backup profile is described
in its [guide](../solr_backup/README.md).

The Solr services use official digest-pinned images, 256 MB heaps and embedded
ZooKeeper through the vendor `solr-foreground -c` command. Native Solr CLI tools
create actual collections using the shipped techproducts configset. Before
module execution, independent HTTP/CLI controls index, query and remove a
document; toggle the real Velocity writer; and create/remove fresh command
markers. They compare the restored writer configuration to its original value.
Native authentication tools configure Basic authentication, and actual HTTP
requests distinguish anonymous/wrong-password 401 from a valid denied role 403.

The selected injection path works through the Config API on Solr 8.3.0. The
8.3.1 default requires a separate JVM system property for parameter templates;
an API configuration update alone does not enable execution. Solr 8.4 removes
that loader. Both negative targets must remain functional search applications
while rejecting the same harmless template. This does not classify every 8.3.1
configuration as fixed: see the [vendor advisory](https://solr.apache.org/security-news2.html#2019-12-30-cve-2019-17558-apache-solr-rce-through-velocityresponsewriter)
and [8.3.1 implementation](https://github.com/apache/lucene-solr/blob/releases/lucene-solr/8.3.1/solr/contrib/velocity/src/java/org/apache/solr/response/VelocityResponseWriter.java).

The version scanner shares these genuine targets. Tests check actual service
rows in a separately connected/migrated Framework database and compare reported
versions to vendor CLI/system-info results. Wrong-password and denied-role
cases exercise the real admin UI asset-version fallback. Credentialed exploit
checks must report the actual accepted credential in that database. Missing
paths and unrelated Apache HTTP must not report a Solr service.

Velocity exploitation can change its writer settings, as the module's Notes
declare. Tests record the post-module state, preserve new target files, then
perform explicit operator restoration before the next iteration. They require
the original logical writer and temporary-file state, with no remaining
sessions/jobs or owned listener ports. This does not claim that Solr's internal
revision counters or logs are rewound. Session transport failures stop the
profile instead of producing later misleading case labels.

Only random loopback HTTP ports are published. Embedded ZooKeeper, Framework
reporting DB and reverse-session listeners stay on container networks; no real
account or Internet callback is used. The [shared runner guide](../README.md)
describes exact-count, current-input, transcript and owned-cleanup gates.

Coverage is limited to these Linux x64 images and selected delivery paths.
Windows/x86 delivery, custom writer names, TLS, custom context paths, later
Solr secure-by-default credentials and the 8.3.1 JVM opt-in remain unqualified.
Existing human module Scenarios are preserved; automated evidence is stored in
the runner's artifact directory.
