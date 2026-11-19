# Native Kafka UI command and session qualification

Verified 2026-11-19 against source SHA-256 `24df3cad90fe9ad2e47e155f3825ab8ebcd8a76ba8233e1a81e5b5b824372c4d`.
The maintained [fixture guide](kafka_ui/README.md), shared Compose services and
[module functional spec](../../spec/modules/exploits/linux/http/kafka_ui_unauth_rce_cve_2023_52251_target_spec.rb)
provide the reproducible setup. No PR was created; the broader goal remains active.

| Profile | Raw cases | Kafka owner cases | Independent handler cases | Owner sessions used/closed |
| --- | ---: | ---: | ---: | ---: |
| `kafka_ui_071` | 13/0 | 9/0 | 4/0 | 6 |
| `kafka_ui_072_groovy` | 13/0 | 9/0 | 4/0 | 6 |
| `kafka_ui_072_default` | 3/0 | 3/0 | 0 | 0 |
| Total | 29/0 | 21/0 | 8/0 | 12 |

The independent controls use eight additional real Framework sessions. All
twenty sessions are used through public APIs and closed. Native prerequisites
are reported separately from Kafka owner cases. This adds one owner and three
qualified profiles, reaching **310 runtime owners in covered paths, 641 qualified
profiles and 4,638 historical functional cases**; the 29 new historical cases
include the eight explicit prerequisite cases.

## Genuine targets and controls

The host uses macOS, Ruby 3.3.13 and the existing Framework bundle. All images run
as `linux/amd64`, with unchanged stock application runtimes. UI processes and
session/file proofs are UID 100. NASM builds the existing source-backed ELF32/64
exit probes; the UI supplies netcat/WGET and has no Bash, curl or Python runtime.

| Target | Upstream reference | Image digest |
| --- | --- | --- |
| Kafka UI 0.7.1 | `56fa824510d8a35b08e3b42bf6625c846e2ed5a0` | `provectuslabs/kafka-ui@sha256:f0ab0eae1fa7fba7d85bcb3e5b8f5a2ab9b8c0d1a2d5e24b9e3d477891eafe95` |
| Kafka UI 0.7.2 | `83b5a60cc08501b570a0c4d0b4cdfceb1b88d6b7` | `provectuslabs/kafka-ui@sha256:4346a0af1450f52286e671a6b49f701d069d7306a802f7cf6743bd27ac4dbcd1` |
| Apache Kafka 3.7.0 | Official stock broker | `apache/kafka@sha256:3e324d2bd331570676436b24f625e5dcf1facdfbd62efcffabc6b69b1abc13cc` |

UI JAR SHA-256 values are `8e35e6e047b5d09e08e9db2062b59207bc94c14d893294b262cbc5086c456afd`
for 0.7.1 and `d5e4c2819cb8c819b0baf9261ce22c63b610bb1d9e5f52ee51424c725e6b2cb3`
for both 0.7.2 configurations. Native before/after checks preserve them.

Native broker bytes, two UI administration cycles, ordinary filter contrast and
real Groovy execution or explicit feature denial calibrate the target before
owner verdicts. Version 0.7.2 has byte-identical version metadata when Groovy is
default-disabled and explicitly enabled, so passive discovery returns Detected.
Core AutoCheck permits that result after warning. No ForceExploit override is
used in this matrix. Disabled filtering produces a specific server rejection,
an operator-facing NotVulnerable failure and restored topic/message state.

Four exact command attempts per profile cover plain text, same-selection quoted/
backslash/dollar repeats, Unicode/emoji/physical newline/tab bytes, and shell
variable/command substitution. Native same-byte proof paths are cleared before
owner execution. Actual owner inputs, passive socket-write buffers, decoded
Groovy queries, response bodies and UID 100 file bytes are audited.

Six owner sessions per positive profile cover netcat, x86/x64 inline HTTP fetch
and staged x64 Meterpreter, including netcat/x64-fetch repeats on the same selected
module. Cached payloads are read without regeneration. Registered ELF bytes are
hashed and matched to running images for inline fetch; the staged case records
its stager and verifies the resulting real Meterpreter APIs/lifecycle. Real
PostgreSQL session owner/payload/workspace rows and closed_at values are checked.
Per-run process, live-connection, FIFO, fetched-file, proof-file, job/session and
native topic/message cleanup are required.

## Confirmed repairs and retained failed attempts

A preceding repair returned Detected for optional 0.7.2 mitigation and Unknown for
unreachable/unusable discovery. Its 19 focused cases retained 12 failures before
repair and zero afterward; six actual check cases passed after native controls.

The published-predecessor command helper failed real quoted, UTF-8 and shell-dollar
commands after identical native controls succeeded. A literal-only candidate
passed its unit tests but failed live because the default Rex query encoder left
backslashes raw. Explicit JSON string serialization, Groovy dollar protection
and per-request strict URI encoding repair delivery. Identical 36-case source
comparisons retain 10 original failures, 3 literal-only failures and zero final
failures. The real socket buffers distinguish valid queries from permissive
URI-parser round trips.

The owner also ignored genuine disabled-feature HTTP400 responses. A focused
response/ensure-cleanup repair retains 50 identical cases with 14 failures before
and zero afterward. It distinguishes the exact feature denial from empty400 or
script-error4002 responses, reports missing/rejected replies, cleans the current
created topic after early produce failure, clears per-run state and preserves
primary errors when cleanup needs manual intervention. Target operations in
those focused fault cases are stubbed; live success and feature-denial paths
are independently verified by this matrix.

Earlier fixture failures remain unqualified: malformed console CMD formatting,
dual-stack callback discovery, an incorrect AutoCheck-Detected oracle, foreground
session interaction without run-z, and repeat state stored in an example-local
variable. Native controls, actual inputs and session/selected-module records
identified those causes. Interrupted stacks were removed before replay. Human
module Scenarios and their following Limitations are byte-for-byte unchanged.

## Verification and lifecycle evidence

Run from the Framework checkout with a unique task namespace:

```sh
export MODULE_TARGET_NAMESPACE="kafka-ui-$$"
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  kafka_ui_071 kafka_ui_072_groovy kafka_ui_072_default
```

The maintained matrix passes 29/0, with **842 native assertions**, **152 zero
resource-event captures**, **77 unchanged declared runtime inputs** and all
**25 recorded owned Docker objects independently absent**. It uses one shared heavy
lock and at most three capped services, removes completed stacks before starting
the next, and preserves unrelated initial containers. Real in-test Psql queries
verify reporting; there is no parallel external reporting observer.

The local immutable capsule `kafka-ui-functional-20261119T170059` contains 545
verified entries; SHA256SUMS digest is
`8248c5761f40d14876b792348742d533acd9eecfb03c8ef53424da5fd0222a67`.
It retains tested inputs, source hashes, raw console/native/wire evidence,
reporting and cleanup receipts. Earlier failure capsules are retained separately.

Focused module specs pass 50/0. New fixture Ruby lint passes with zero offenses;
module/spec lint and msftidy retain one inherited ModuleDefaultPayload offense,
with zero new offenses. Module documentation validation passes. The full RSpec
suite was not requested or run.

## Summary

One source owner now has three maintained, independently calibrated profiles.
Command delivery, optional mitigation, reporting and repeated session lifecycles
are verified in the covered paths.

## What looks good

Stock image identity, native contrast, same-byte inputs, observed wire buffers,
used/closed sessions and physical cleanup jointly support the result. Failed
setups and module defects have separate retained evidence; registration is not
used as proof of coverage.

## Concerns

The inherited default-payload lint offense remains. Other releases, authentication
modes, nondefault cluster names/routing, architectures/transports and concurrent
target changes are unqualified. Early produce and cleanup fault contracts have
focused stubbed coverage, rather than a complete native ACL/fault matrix.

## Suggestions

Use the guarded namespaced launcher for future runs and continue the remaining
module-feasibility queue. Keep additional target modes separate until their
native prerequisites and real owner outcomes can be demonstrated.
