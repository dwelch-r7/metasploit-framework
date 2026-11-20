# Cacti container qualification

Four maintained owner profiles pass **24/0**, including **15 used and closed
sessions**: nine Cacti sessions and six independent handler controls. Two older
release controls also pass **2/0**, without qualifying an owner. The stock PHP
profile records one failed native readiness control and two withheld owner cases.

This adds one owner and four qualified profiles, reaching **313 runtime owners
in covered paths, 651 qualified profiles and 4,711 historical functional cases**.
The broader campaign remains active. No PR was created.

## Confirmed discovery repair

`LOCAL_DATA_ID` without `HOST_ID` previously searched with `@local_data_ids`
(plural, nil). The one-character repair preserves the supplied ID while finding
the host. The focused regression changed from **13 examples / 4 failures** to
**13/0**. Real command-discovery controls changed from **4 examples / 1 failure**
to **4/0**, with all 16 non-module inputs identical between those native runs.

The repair is published in the fork as
[`ff8a5836f4c`](https://github.com/dwelch-r7/metasploit-framework/commit/ff8a5836f4cde312cdd6b41f710f0fa5714b66f1).
No pull request was created.

## Proof-process lifecycle repair

The first maintained session replay exposed a shared test-harness defect.
Native x86/x64 handlers reached ready, correctly labelled sessions, but their
`/bin/touch` proof files sometimes never appeared. The shared helper immediately
called `process.close` after RPC acceptance. Installed Mettle 1.0.48 implements
that close by sending SIGINT to the child, so it can interrupt the operation.
This is not evidence that the Cacti exploit failed.

The repair preserves the identical command, arguments and launch flags. It
observes a zero-byte regular proof through the public file API before active
close, retains the child PID and independently queries child absence afterward.
The external Docker/file/bytes/UID assertion remains unchanged. Shell proof
behavior and existing return fields are preserved.

Identical focused tests changed from **14 examples / 10 failures** to **14/0**;
syntax and lint pass. A private native diagnostic remained unqualified after
setup and observer errors; its failures are retained separately. Qualification
comes from the normal maintained default profile, which passed **3/0** with
three used/closed sessions and child PIDs **797, 962 and 1118** observed before
close and absent afterward. Its seven Docker objects were independently absent.

The installed executable and stage function bytes were checked against
[Mettle's close implementation](https://github.com/rapid7/mettle/blob/46ebde9db0c25d0c8cf287469f091266c4e9c3d5/mettle/src/stdapi/sys/process.c#L172-L184).
The historical failing run discarded its child PID, so exact delivery of SIGINT
in that particular failure was not captured. The unsafe ordering itself is
established independently.

## Maintained profiles

See [setup and commands](cacti/README.md). Each profile uses a genuine application,
native prerequisite controls and a serial capped stack.

| Profile | Cases | Current evidence |
| --- | ---: | --- |
| `cacti_1222_default` | 3 | Passed 3/0 after the proof repair; three sessions used/closed |
| `cacti_1222` | 6 | Passed 6/0: refused port, exact commands and manual/automatic/partial IDs |
| `cacti_1223` | 3 | Passed 3/0: native fixed-release controls, Safe and both AutoCheck refusals |
| `cacti_1222_sessions` | 12 | Passed 12/0: five handlers and seven owner sessions used/closed |
| `cacti_1222_php` | 3 | One failed native readiness control; two owner cases withheld |
| `cacti_1216` | 1 | Passed 1/0, native-only control |
| `cacti_1217` | 1 | Passed 1/0, native-only control |

The older-release controls do not invoke the Framework owner and do not qualify
an owner profile. Earlier native controls established that 1.2.16 allowed local
command execution while its public forwarded-header path was denied. Complete
upstream 1.2.17 allowed both local/public first and repeated probes. For 1.2.23,
legitimate forwarded polling still worked, while all four local/public command
probes produced no marker. This does not establish that every trust mechanism was
removed by the command-injection fix.

## Focused and shared verification

The final root suite passes **27 focused cases**: thirteen Cacti discovery cases
and fourteen proof-lifecycle cases. Its raw **34/0** includes seven automatically
loaded acceptance-formatting support cases. Changed Ruby passes RuboCop; module
and module-document tidy, Python parsing and both shell syntax checks pass.
These checks retain 39 files in `cacti-publication-checks-20261120T154740`, manifest
`fa14d1cce6896d66b28f040a4d0d737712415752e3f0c2667f6db730b94e7257`.

The existing `kafka_ui_071` regression passes **13/0** with the repaired shared
helper: four independent handlers and six owner sessions are used and closed.
Its seven Meterpreter proof children are observed before close and absent after;
physical files match exact bytes and UID 100, then disappear. All declared inputs
remain unchanged, cleanup has no errors and all nine Docker objects are absent.
This adds no campaign counts. The 229-file capsule is
`cacti-shared-proof-kafka-regression-20261120T153453`, manifest
`cc79c65cce23084c0dc440634ef89e91cfde2aa7d810c2e80dcecf8737e12481`.
It also retains the separate parent audit of all fifteen Cacti physical proofs.

Inspected Python and PHP fixtures use their own Meterpreter file-write proof APIs;
their calls to this helper use its unchanged shell branch. They were not rerun as
evidence for the changed Meterpreter process branch. No full RSpec suite was run.

## Limits and retained failures

The final direct stock PHP Meterpreter control again failed readiness before
proof, with no owner exploit invoked and no cleanup error. Earlier direct stock
controls repeatedly received their stage without a usable session. A separate
stock diagnostic reached readiness through
a timing-changing proxy, then stopped at a metadata guard before proof. Its
cause remains unclassified. A private PHP framing patch was tested separately
and is not installed by these fixtures or counted as stock qualification.

The stock image lacks Netcat. That runtime path is outside the qualified fixture
coverage. The module's payload catalog and existing defaults remain unchanged.
Narrow, explained lint exceptions preserve the established Bash/x86 choices;
normalized executable Ruby AST is identical to the discovery repair.

## Evidence and cleanup

All declared inputs, native commands, owner observations, reporting queries,
resource readings and cleanup logs remain tied to their run directories. Failed
setups and interrupted controls were retained without converting them into
module verdicts. The original human-written module Scenarios are unchanged:
11,225 bytes, SHA-256
`69ac03415d4e0c2446aab710f3611999d3c62c08db471af12a5445afc619117e`.

The repaired maintained default run is sealed at
`cacti-maintained-default-proof-fixed-20261120T150425`: **159 files**, manifest
SHA-256 `9dc01958b3755cf9dabe3b33657ed9be417a2f7d18f75aaf62dcad86982e3b74`.
The interrupted maintained run retained its 31 independently absent Docker
objects at `cacti-maintained-interrupted-20261120T141731`, manifest
`71bde70117331fe308b1256a6e75130aa512d230226f1a5bffbb2e8f600fe72f`.

The complete maintained matrix, including the failed PHP prerequisite, is sealed
at `cacti-maintained-matrix-20261120T151721`: **568 files**, manifest SHA-256
`36f8b8596fd4313a7ac6fb50ef19f3ca970a6ba041431270bedab32be66d5056`.
Its parent audit verifies unchanged declared inputs, all 15 unique persisted
session rows and closure timestamps, UID 33 and physical file proofs, generated
ELF hashes, repeated module selection and independent listener refusal. All
12 Meterpreter proof children were observed before close and absent afterward.
The retained records include 794 native assertions and 114 zero-valued SDK
resource readings. At most three capped containers ran together; all **41**
observed containers, ephemeral networks and volumes were independently absent.

The user separately authorized removing every container unused by this work.
After the matrix ended, six unrelated unused containers were removed; an
unfiltered inventory including stopped containers then contained zero entries.
This one-time cleanup did not delete volumes or change the routine ownership
policy.

Source/helper repairs and fixture qualification remain separate from upstream
submission. Only normal pushes to the user's public fork are authorized; no PR
or external comment is part of this campaign.

## Summary

The fixtures qualify commands, discovery, real sessions, repeats and fixed-release
refusal for the covered Cacti paths; the short default profile contains three cases.

## What looks good

Native controls establish prerequisites separately, observers retain actual owner
calls and bytes, and physical/reporting evidence verifies session use and cleanup.
The confirmed module repair and shared harness repair have distinct regression
evidence. Existing payload defaults and human Scenarios are preserved.

## Concerns

Stock PHP readiness remains unresolved. Netcat, other releases/architectures,
TLS, custom prefixes, authentication variants, concurrent poller changes and
injected transport failures remain unqualified. Passing older-release native
controls do not establish owner compatibility for those releases.

## Suggestions

Continue the PHP transport investigation separately, retaining the independent
readiness gate and stock dependency. Do not turn the withheld cases into module
passes by applying the private framing experiment.
