# Elasticsearch memory disclosure target

This lab exercises the public `check`, SCAN and DUMP entrypoints of
`auxiliary/scanner/http/elasticsearch_memory_disclosure`. It uses genuine
Elasticsearch processes and an ordinary PostgreSQL role/database for Framework
reports. HTTP transport, scanner dispatch, response parsing, reporting and loot
storage remain enabled. The module's human-written guide and Scenarios are
left intact.

The [vendor advisory](https://discuss.elastic.co/t/elasticsearch-7-13-4-security-update/279177)
identifies affected releases 7.10.0–7.13.3 and fixed release 7.13.4.
`images.json` records the official multi-architecture image digests used here.
These profiles cover one affected/fixed pair, rather than every affected release.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb elasticsearch_memory elasticsearch_memory_fixed elasticsearch_memory_secured elasticsearch_memory_unpooled elasticsearch_memory_unrelated
```

Profiles run serially with two capped containers each. Normal Elasticsearch
uses one CPU, 2 GiB memory/swap and a 1,280 MiB Java heap; PostgreSQL uses
0.25 CPU and 384 MiB. The unpooled profile uses 768 MiB for Elasticsearch and
a 256 MiB heap. The unrelated Apache application uses 0.25 CPU and 128 MiB.
Every container has a PID limit of 128 and init enabled. Published application
and database ports bind only to loopback. The guarded launcher refuses existing
containers, isolates console configuration and removes each project's containers,
attached volumes and networks before continuing.

| Profile | Native state | Cases |
| --- | --- | ---: |
| `elasticsearch_memory` | 7.13.2, security disabled, normal pooled allocator | 8 |
| `elasticsearch_memory_fixed` | 7.13.4 with the same pooled configuration | 4 |
| `elasticsearch_memory_secured` | 7.13.2 with real native users and roles | 9 |
| `elasticsearch_memory_unpooled` | 7.13.2 with the normal low-heap allocator | 4 |
| `elasticsearch_memory_unrelated` | Real unrelated Apache site | 3 |

Heap size matters. The affected version's
[normal allocator selection](https://github.com/elastic/elasticsearch/blob/v7.13.2/modules/transport-netty4/src/main/java/org/elasticsearch/transport/NettyAllocator.java)
uses unpooled buffers at heaps of at most 1 GiB. The larger heap activates its
normal pooled allocator without forcing private allocator flags or modifying
the application. Native controls verify the actual JVM heap, version, Java UID,
document reads/writes and malformed bulk response. Before/after controls verify
unchanged document content and zero OOM, OOM-kill and PID-limit events.

The secured profile creates an administrator, a read/write account, a read-only
account with cluster monitoring, and a read-only account without cluster
monitoring. Real native requests verify write denials and cluster-information
denial. Malformed bulk parsing still exposes the affected buffer for the latter
accounts. A failed passive version check therefore cannot gate active collection.
Anonymous and incorrect-password requests must produce no loot or vulnerability
reports. These are public demonstration credentials: `elastic`, `module_writer`,
`module_reader` and `module_limited` use `module-target-password`.

Repeated calls cover both actions, `LEAK_COUNT=2`, actual missing handlers,
nonexistent-index checks, unavailable connections and a host range containing a
unreachable address followed by the live target. DUMP files must exactly match the
backing-buffer intervals in the same call's real `HttpTrace` responses. Console
traces retain their content lengths; no second request stands in for a dynamic
disclosure. Real workspace reports must deduplicate correctly. Sessions and jobs
must remain empty. Fixed responses describe a `ByteArrayInputStream` and must
create no disclosure report or loot.

HTTP framing outside the malformed two-byte JSON body demonstrates backing-buffer
exposure. Earlier index metadata or credentials provide stronger evidence of
prior traffic when actually present; the tests record that distinction. Buffer
contents vary, so the lab does not promise a specific secret or document canary.
Setup or native-control failures require investigation before a module verdict.
