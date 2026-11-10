# OpenTSDB and integrated checkpoint, November 10

Current passing records establish **173 runtime modules, 107 families and 1,359
functional cases**. Two OpenTSDB modules add 49 cases to the
[Druid checkpoint](VERIFICATION-20261110-druid-compact.md). The full campaign
remains incomplete. Both OpenTSDB production modules are unchanged.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb opentsdb_yrange opentsdb_yrange_fixed opentsdb_key opentsdb_key_fixed
```

Each serial project has four containers: one genuine OpenTSDB/HBase, an Apache
Basic-auth prefix gateway, unrelated Apache and Framework. The pinned 2.4.0
image retains its vendor entrypoint, Java8u302, HBase2.4.5 and Gnuplot5.4.1.
All23 runtime JARs match the official Debian package. The 2.4.1 build installs
the official package with its recorded SHA-256; the fixed build uses actual
2.5.0-RC1 source revision `0f681b7545d9999506900da5f1c4dbe433dbfb43`, replacing
the full runtime/dependencies/UI. No released 2.4.2 image is invented. Build
recipes, publisher/source URLs, observed provenance and source-visible native
ELF controls are retained; external package/dependency mirrors remain build
prerequisites.

| Profile | Release | Cases/failures | RSpec seconds including bootstrap |
| --- | --- | ---: | ---: |
| yrange affected |2.4.0|19/0|205.072615|
| yrange fixed |2.4.1|6/0|54.238777|
| key affected |2.4.1|18/0|325.942046|
| key fixed |2.5.0-RC1|6/0|109.769836|

All four profiles complete naturally in invocation `20261110T124008-ac1455`,
with zero pending/outside errors and successful teardown. Parent imports and
byte-checks all235 original invocation files, all78 inputs per profile and the
87-input union. Runtime/lab revision is `8399cead894`; parent fixture commits
are `04974b719eb` and `4b5c938f687`.

There are98 public operations:40 checks and58 runs, with46 actual owner command
calls. Twelve shell/Meterpreter sessions open, execute remote proof and close
with their target PIDs absent. Unix Bash, Linux x64/x86, curl/wget/Bourne and
Fetch delivery are exercised through the supported public targets. Exact simple,
quote, backslash, plus and chmod-string values repeat. The Linux-only key module
uses genuine compatible Fetch exec payloads: those vectors prove the downloaded
program's command bytes, while the recorded owner argument is its actual Fetch
wrapper. They do not claim arbitrary raw key-argument byte preservation.

Native gates retain220 CLI and488 HTTP records, separate from668 harness CLI
records. They verify actual versions/JARs/UID, six real time-series points,
all3 metrics ×35 aggregators, real JSON queries/PNG graphs, Basic acceptance and
refusal, missing/unrelated routes, actual x86/x64 ELF exit42 and repeated genuine
execution/refusal controls. Every fixed native refusal needs the actual validation
reason, excluding malformed URL-decoding errors. Normal prompt/isolated BOOT and
within-invocation metadata validation remain recorded. Later transcript audits
are labelled post-terminal, rather than claiming contemporaneous observation
of every profile.

The original `20261110T111836-fa400f` retains49/20 as a diagnostic result. Its key18
cases fail in a native producer before any module runs: 2.4.1 performs another
URL decode and the producer had not protected literal percent bytes. Its yrange
gateway fails because timeout0 cannot receive a Basic challenge. Key tests also
selected an incompatible Unix payload, and early forced-negative assertions could
pass without reaching execution. These are preserved fixture limitations, not
20 production-module defects.

The corrected producer follows actual single/double GraphHandler decoding.
Gateway runs set existing public `HttpClientTimeout=5` for bounded Basic
negotiation. Genuine compatibility selection and actual execute-call assertions
prevent the earlier false-negative passes. No SDK, runner, module defaults,
production code or shared timeout changes were made.

Top-level temporary files, actual Java daemon PIDs and listeners are checked.
Proof files and default retained Fetch files have explicit operator cleanup;
requested Fetch deletion and dropper removal are checked separately. Disposable
graph/HBase caches are not presented as automatic module cleanup. Other releases,
backends, OS/CPU targets, TLS, empty metric stores and arbitrary Gnuplot syntax
remain unqualified.

Parent verifies20 exact objects absent—16 containers and four networks—and12
empty project-label queries. Docker is empty at the12:58:40Z terminal audit.
Each later campaign project receives a separate serial grant. Only campaign
containers may run, with at most five containers and full teardown per project.

Two new Ruby files lint cleanly, two Python syntax checks and selected dry
19/6/18/6 pass. Both original human-written documentation prefixes remain exact
(7,239/6,439 bytes); all six existing docs warnings are unchanged. A temporary
baseline-path observer mistake is retained separately from the corrected
comparison. No full local RSpec suite is claimed.

The complete1,039-entry worker seal is
`/Users/dwelch/.codex/reports/opentsdb-validation-20261110-8399cead894`,
manifest SHA-256
`c6633dcd99fc94fb893c1f55aeeb2c8177e34d1cce709b77b3000a42b6c43dba`.
It includes the original292-file baseline seal, current raw run, all87 source
copies, native preparation and both patches. The27-entry parent seal is
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-4b5c938f687`,
manifest SHA-256
`db23ef4cbcaa907373da9292faf92c4de3be6fa41a01919bfa12884fbdf39f8c`.
