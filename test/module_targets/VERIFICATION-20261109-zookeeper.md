# Complete ZooKeeper information replies

The selected checkpoint covers **120 runtime modules, 55 families and 755
functional cases**. Every selected profile has exact expected counts, zero
failures, pending or outside errors, current recorded input hashes and owned
teardown. This adds one module and nine cases to the
[preceding checkpoint](VERIFICATION-20261109-etcd.md). The broader goal remains
active. No PR was created or full local RSpec suite run.

## Genuine targets and collection

The [normal lab](zookeeper/README.md) runs official digest-pinned ZooKeeper
3.4.14 and 3.9.3 on Linux amd64. Five policies allow both information commands,
each separately or neither. Vendor CLI/configuration and fifteen complete
native TCP reads independently establish versions, permissions and actual
environment/statistics. Ordinary Apache supplies the unrelated-service control.
The legacy image uses its supported `ZOO_CFG_EXTRA` configuration; the modern
restricted profile retains the image's `srvr` policy.

Eight normal cases perform thirteen module runs. Permitted loot must match
every native environment field and meaningful statistics, with structural
checks for changing memory/counters. Each permission policy repeats. Zero
selects the documented default timeout; an explicit one-second probe also
succeeds. Denied/unrelated paths must not create unexpected loot.

The [transport extension](zookeeper_segmented/README.md) reuses the genuine
3.9.3 server through official Toxiproxy 2.9.0. Its downstream slicer configures
an average of 640 bytes and 150-millisecond delay; actual chunk sizes are
retained. Native EOF reads verify complete upstream content through the altered
transport, without replacing service replies. Its single case repeats complete
module collection twice with the existing five-second TIMEOUT option.

## Reproduced failure and repair

| Canonical run | Family | Cases/failures | RSpec seconds |
| --- | --- | --- | --- |
| `20261109T222537-6a34f2` | normal, original source | 8/0 | 123.453959 |
| `20261109T225712-2e7bd0` | sliced, original source | 1/1 | 69.841524 |
| `20261109T231052-c52843` | normal, repaired source | 8/0 | 109.344052 |
| `20261109T231052-c52843` | sliced, repaired source | 1/0 | 19.191340 |

All four profiles complete naturally with zero pending/outside errors, passing
native controls and passing teardown. A separate early native preparation
failure compared a vendor CLI's extra shutdown log to the entire version
string. Parsing its unique exact version line fixes that setup assertion; raw
output and earlier inputs remain retained.

The sliced baseline proves silent truncation. Native reads recover 4,320 bytes
and all eighteen environment fields in about 1.2 seconds. The module saves the
exact first 540-byte prefix and only six fields. Version and hostname fit in
that prefix, so its success output conceals missing OS/user information.

The owning repair uses the existing Rex stream reader until each four-letter
reply's EOF, with both read bounds set to the existing timeout and the outer
deadline preserved. Setting the quiet-gap bound matters: the reader's ordinary
100-millisecond default is shorter than the actual 150-millisecond gaps. EOF
gets operation-context output and developer logging; ensured disconnect remains.
RPORT 2181 moves to DefaultOptions while preserving the public default and
removing duplicate mixin registration.

Synthetic EOF-contract examples improve **8/1 to 8/0**, including seven shared
examples. A later default-port assertion yields final **9/0**; it was not in
the original eight-case unit baseline. These are explicit synthetic boundaries,
not native EOF captures. Four changed/new Ruby files lint with zero offenses;
the original source had two inherited offenses. Module tidy and documentation
checks pass. The entire historical console block remains byte-identical.

## Integrity, cleanup and limits

All original 31 normal and 30 sliced inputs were copied and hash-verified before
the source repair. Final input keys are identical. The normal set changes only
owning source; the sliced set changes owning source and a README correction
distinguishing configured average from actual chunk sizes. Functional/native
assertions are unchanged. No shared runner, helper, dependency or timeout was
changed. Both final sets match current source.

All four runner projects and **36** recorded anonymous volumes independently
audit absent, as do three native preparation projects and their recorded
volumes. The durable `zookeeper-module-validation-20261109-027c8ea2e00` export
retains failed/passing runs, hidden metadata, exact earlier/final inputs, native
preparations, source, units and checks. All **404** export checksums were
independently reread and verified; its manifest SHA-256 is
`72191c9117eb652a33a72cebb188692b58250734e30ab4afbec358f6ac295917`.

Other releases/architectures, TLS/SASL client operations, ensembles/quorum,
HTTP administration and unusual TCP failure timings remain unqualified. These
information cases make no session/exploitation claim. Declared input hashes
are not the entire dependency graph. The aggregate selector is
`tmp/module-target-checkpoint-zookeeper-repaired-current.json`; its sole warning
is the unqualified WordPress admin reproducer. Ansible retains an explicitly
[deferred investigation](DEFERRED.md). RabbitMQ/Erlang, Kubernetes and Solr have
separate qualification work in progress and do not add to this count.

Fork CI is separate: the preceding pushed revision has six completed successful
workflows and four queued at the latest inspection. Earlier Verify runs retain
an unclassified OpenSSL certificate-example failure. No overall green claim is
made.
