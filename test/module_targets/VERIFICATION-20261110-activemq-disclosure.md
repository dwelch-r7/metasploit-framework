# ActiveMQ source disclosure qualification, November 10

The `activemq_disclosure` profile qualifies
`auxiliary/scanner/http/apache_activemq_source_disclosure` against genuine
ActiveMQ 5.3.1, fixed 5.3.2 and unrelated Apache HTTP. The
[target guide](activemq_disclosure/README.md) records verified archive provenance,
pinned images, native controls and reproduction.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb activemq_disclosure
```

## Results and attribution

| Invocation | Cases | Failures | RSpec seconds | Inputs |
| --- | ---: | ---: | ---: | ---: |
| First original `20261110T031223-72ec34` | 8 | 6 | 74.136290 | 40 |
| Corrected original `20261110T032340-f5f143` | 8 | 6 | 83.634978 | 40 |
| Final `20261110T034630-d5cc0a` | 8 | 0 | 100.023509 | 43 |

The first original run includes a fixture error: `//admin/queues.jsp` is parsed
as a URI authority, producing `/queues.jsp`. The corrected baseline changes only
that fixture to the accepted `/admin/queues.jsp`; production is unchanged. All
six remaining failures are direct source/body defects: three stock pages save
rendered HTML, while fixed/static/unrelated HTTP 200 bodies also become loot.

Native raw double-slash responses match stock filesystem JSP hashes, ordinary
paths render HTML, and the fixed version refuses the traversal. The owning repair
adds the exploit slash after path normalization and requires raw JSP syntax
before storing the exact response bytes. Port defaults and Notes are updated
within the owning module. No shared URI/parser implementation changes.

The final run completes naturally with zero pending/outside-example errors and
passed teardown. Six loot files match the three genuine stock JSP sources twice
each; fixed, missing, static and unrelated controls refuse disclosure. Native
gates pass 28 CLI operations and 17 HTTP requests, including actual JMS round
trips, queue removal, Java version and source-hash comparisons. Targets and the
corrected acceptance assertions remain byte-identical across the matched repair.

Focused examples reproduce 22/9 to 22/0, including seven shared formatter
examples. The parent independently passes all 22 and lint on five Ruby files.
Module/doc tidy passes; no human Scenarios were invented. The manifest's three
added inputs are the focused spec and two captured fixtures. Existing-key changes
are confined to the module and manifest.

## Evidence and limits

The parent copied and byte-checked the complete 53-file final invocation and
verified all 43 runtime inputs current. It also matches all 45 sealed source and
documentation files to the checkout. Exact resource audits confirm four final
containers and their network absent; there are no volumes.

The unchanged export is
`/Users/dwelch/.codex/reports/activemq-disclosure-20261110-5aa130edea7`.
The parent independently verified all 419 entries in `SHA256SUMS`, whose SHA-256
is `b284b405180ff42bcb87f4e468aae1afd85aad6ab9ecd81ee1f2b41dbcd43ec7`.
It retains all three invocations, frozen sources, signed-archive validation,
native captures, image comparisons, focused regressions and cleanup. RootFS
layers match between runs; differing broker image configuration is limited to
the invocation's Compose project label. Raw evidence stays outside Git.

This qualifies Linux amd64, plaintext anonymous stock HTTP and these exact
releases/pages. Arbitrary HTTP 200 content is not disclosure proof. Other JSP
dialects, versions, custom authentication, TLS, IPv6 and Windows/backslash modules
remain unqualified. The separate FileServer exploit has no qualification in this
reader result.
