# ActiveMQ Jolokia qualification, November 10

The `activemq_jolokia` family qualifies
`exploit/multi/http/apache_activemq_jolokia_rce` against genuine ActiveMQ 5.19.3
and fixed 5.19.4 brokers. The [target guide](activemq_jolokia/README.md) records
publisher-verified archives, pinned Java runtime, native controls, credentials
and limits. This is an addition to the ongoing campaign, not its completion.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb activemq_jolokia
```

## Results and parent verification

Strict final invocation `20261110T022600-359579` passes **18 cases, zero failures**
in 382.202588 RSpec seconds, with zero pending/outside-example errors and passed
teardown. All 62 recorded input hashes match the integrated files. The parent
copied and independently byte-checked all 61 files in the complete invocation,
retaining its original revision, paths, commands and isolated metadata snapshots.
Independent exact-project inspection confirms all five containers and their
network are absent; this family uses no named volume.

Six sessions were actually used for target command/file-owner proof: two Bash
shells and four Linux Meterpreter sessions using both shared and separate HTTP
fetch ports. Eleven sessions opened in total; opened sessions alone are not the
success criterion. Positive executions have 16 genuine JSON status-200/NC
creation receipts and 16 confirmed owning-removal receipts. Repeated commands,
sessions, exact broker connector/bridge graphs, temporary files, callback
resources and actual listener refusal are checked. Positive output must reject
uncertain creation and unconfirmed cleanup warnings.

The earlier repaired matched invocation `20261110T021601-171a05` also passes
18/0 in 411.082619 seconds. Its independent transcript audit found no such
warnings. A separate assertion-only commit adds the explicit warning gate;
the final replay changes only that spec among the same 62 recorded inputs.
Production source, native controls, images and target guide remain unchanged.
The before/final broker image filesystem layers are byte-identical; per-project
image configuration differs only in Compose labels.

Parent focused tests pass 48/0 (41 owning regressions plus seven existing shared
formatter examples). Four changed Ruby files pass lint and the module passes
msftidy. The module guide passes documentation tidy and retains its human-written
Scenarios. No shared runner, timeout, handler or payload implementation changed.

The self-contained immutable export is
`/Users/dwelch/.codex/reports/activemq-jolokia-20261110-c2f29f3c601`.
The parent independently verified all 666 entries in `SHA256SUMS`, whose SHA-256
is `61be637d065496e2a12893cb24d4a61dbfdadea952ccecece938feba66378b9f`,
and checked all 64 sealed current-source files against the integrated checkout.
It retains all five invocations, atomic metadata, original/corrected input maps,
native controls, receipts, vendor logs/source and the three separate patches.
The parent also independently inspected all nine retained broker image IDs:
across both matched comparisons, filesystem layers match exactly and the sole
configuration difference is the Compose project label. Raw evidence stays
outside Git. All 38 native/runner entities (31 containers, seven networks) have
independent absence receipts; no named volumes were used.

## Native controls and original failures

The independent native gate records 111 commands and 50 HTTP observations.
It uses actual vendor JMS/OpenWire, curl, JDK HTTP and broker JMX APIs, including
real `ProcessBuilder` proof whose owner and parent PID match the broker JVM.
It verifies genuine root/prefix contexts, custom broker names, both admin and
user credentials, Origin policy, fixed-release refusal, JMS message round trips,
actual TCP bridges and exact connector/tmp restoration. Broker logs and native
response bytes remain evidence; responses and sessions are not simulated.

The first original invocation `20261110T013815-d0aa4a` timed out before the initial
console prompt and has no module/native observations. It remains a setup failure
of unknown cause. The untouched retry `20261110T014646-13fa9c` returns 18/14 in
298.583145 seconds. One canary assertion incorrectly rejected a legitimate Java
exception name in native HTTP trace data; its actual bridge damage was already
recorded. Correcting only that matcher and replaying the unchanged module in
`20261110T015950-ce4cad` still returns 18/14 in 252.390141 seconds.

The original module omitted Origin from discovery, accepted Jolokia HTTP 200
without validating its JSON status/product, and did not classify the broker fix
boundary. It could fall back to the wrong broker name. It also removed an existing
NC before creating its own connector: preserved native graphs demonstrate that
an actual TCP bridge disappeared even when an NC name remained. The source repair
uses authenticated Origin-aware broker discovery, validates product/version and
API receipts, and refuses an existing NC before mutation. It removes only the
connector positively accepted by that run, preserves parent cleanup, and reports
uncertain execution/state when no trustworthy receipt exists. Invalid CDATA is
rejected before target operations; unrelated callback paths are not served XML.

One first-original POST with no response, XML fetch or session remains an
unclassified transient. It did not justify adding a callback wait or changing
the module's handler/timeout behavior. Unsupported exploratory unit demands were
also excluded before the final source-only matched corpus was frozen. The final
48-example corpus reproduces 32 failures on the original source and zero after.

## Limits

This covers the specified Linux brokers, HTTP root/prefix paths, broker discovery,
explicit names, accepted/refused credentials, fixed/unrelated products, AutoCheck
and handler modes, command encoding, Bash and Linux HTTP-fetch Meterpreter.
ActiveMQ 6.x version boundaries have clearly derived focused tests, not native
runtime qualification. Windows, TLS, other architectures, alternate commands,
legacy FileServer/JSP and source-disclosure modules remain separate work.

Missing/error/malformed creation receipts require manual broker inspection.
The module deliberately avoids deleting state whose ownership is uncertain.
The successful live paths all have positive creation receipts; focused derived
tests cover uncertain-response and cleanup-error contracts.
