# Publication CI follow-up, 2026-11-16

The published checkpoint is `25f037151179faa0f3f5a730ea9da7a749b967ca`.
Both selected Ruby 3.3 jobs check out that exact fork commit and execute all
40 new BookingPress contract examples successfully. This is distinct from the
native payload jobs' actual Framework checkout.

| Ruby 3.3 job | First attempt | Built-in retry | Actual checkout |
| --- | --- | --- | --- |
| [Normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310150/job/133018895102) | 19,587 examples, 10 failures, 33 pending; seed 27511 | 17 examples, zero failures; seed 6203 | `25f037151179` |
| [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310150/job/133018895052) | 19,400 examples, zero failures, 664 pending; seed 6561 | None needed | `25f037151179` |

The ten first-attempt failures are the existing Fetch HTTP service ownership
examples: WebMock blocks their real localhost requests with
NetConnectNotAllowedError. All ten pass in the built-in retry; seven already
loaded DatastoreFormatting examples account for the other retry examples.
This is recorded as an order-dependent test-isolation investigation. The
contaminating group and base-versus-checkpoint causality were not reproduced;
no Fetch production failure or BookingPress regression is inferred from it.
There was no agent-initiated retry or cancellation.

The six-entry read-only unit CI seal is
`/Users/dwelch/.codex/reports/bookingpress-publication-unit-ci-20261116`;
manifest SHA256 `7dd53cd802fbff57443ad2b7964db877214a877829507088e27f863fcbe536aa`.
It retains the complete logs, job metadata and exact-checkout/group audit.

## Selected native job context

| Job | Result | Seed | Actual Framework checkout |
| --- | --- | --- | --- |
| [Linux Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310242/job/133018896052) | 51 examples, zero failures | 33664 | `bea1fb069e79cb610fe3981f16b8697790369c63` |
| [macOS Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310242/job/133018896248) | 46 examples, zero failures | 17518 | `bea1fb069e79cb610fe3981f16b8697790369c63` |
| [macOS Python 3.11](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310242/job/133018896219) | 91 examples, zero failures | 18117 | `bea1fb069e79cb610fe3981f16b8697790369c63` |
| [macOS Python 3.8](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310242/job/133018896277) | 91 examples, zero failures | 36452 | `bea1fb069e79cb610fe3981f16b8697790369c63` |

These jobs report successful conclusions, including their artifact stages.
Their workflow metadata names the fork checkpoint, but their actual Framework
checkout is upstream. Binary source and package provenance were not audited;
these results do not add runtime qualification for the fork's module changes.
The eight-entry read-only context seal is
`/Users/dwelch/.codex/reports/bookingpress-publication-native-context-ci-20261116`;
manifest SHA256 `55a445fd05d8e759d36c4b2d091dc879ffbe2ee2167ea65f2e278cbeee6ebadf`.

## Terminal BookingPress result

The final 2026-11-16 02:37 UTC snapshot is terminal: ten workflows succeed,
63 checks succeed and one is skipped. The last Python 3.8 macOS job and
[Generate report](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310242/job/133038845886)
both complete successfully. The earlier 01:27 snapshot was partial; all test
jobs finishing did not establish that the final report had finished.
The eight-entry read-only terminal seal is
`/Users/dwelch/.codex/reports/bookingpress-publication-terminal-ci-20261116`;
manifest SHA256 `6ba1600fb053a29c8952a26a1a84d3c26655b7bc3c9ff236ad42fb869d76cdb9`.

## Duplicator publication result

Checkpoint `0593c396fc4ce9940bfd0f7a12e4a2209c8867ac` also finishes all ten
workflows successfully, with 63 successful checks and one skip. Both selected
Ruby 3.3 jobs check out that exact fork commit and execute all 41 Duplicator
contract examples successfully on their first attempt.

| Ruby 3.3 job | First attempt | Built-in retry |
| --- | --- | --- |
| [Normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43787446532/job/133038148744) | 19,628 examples, zero failures, 33 pending; seed 7719 | None needed |
| [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43787446532/job/133038148712) | 19,441 examples, one failure, 664 pending; seed 44695 | Eight examples, zero failures; seed 12500 |

The REMOTE_DB failure is the SNMP incomplete-reply timeout contract: expected
`[nil, reply]`, observed `[reply, nil]`. The retry selects that one example;
seven already loaded DatastoreFormatting support examples make up its other
cases. The follow-up scopes the SNMP spec's `IO.select` stubs to its owned
socket arguments and retains real behavior for unrelated descriptors. A
20-case comparison preserves every existing assertion: unscoped code has one
failure in the added real-pipe isolation case; scoped code passes all 20.
An identical single-example interleaver then reproduces `[reply, nil]` before
and preserves `[nil, reply]` after. The actual unlabelled CI caller remains
unknown; this establishes the interference mechanism without identifying that
caller. Production SNMP source is unchanged. There was no agent-initiated CI
retry or cancellation.

The spec-only worker commit is `de0c64d7d36c2f3b254a01d1f5f9d814a64591b7`,
imported as `93a253d7d23`. Strict original/final lint both retain the same eight
baseline convention findings at lines 10–30; no new offense is introduced.
Syntax and diff checks pass. The 106-entry read-only evidence seal is
`/Users/dwelch/.codex/reports/snmp-recv-wrapper-isolation-20261116`;
manifest SHA256 `f01316817242e96887259d0eb88f75564775e73729527ad95afdeda4cc32ad03`.
The parent independently rehashed all entries. The 20-case snapshots have the
same case/assertion set; their file IDs alter RSpec's seeded order. The exact
one-example interleaver avoids that order difference.

Selected native context jobs pass: Linux Mettle 51 examples, macOS Mettle 46,
and macOS Python 3.11 and 3.8 each 91, all with zero failures. Their actual
Framework checkout is upstream `bea1fb069e79cb610fe3981f16b8697790369c63`.
They provide upstream native context; they do not establish execution of the
fork's Duplicator code. Binary/package bytes were not audited.

The 17-entry read-only CI seal is
`/Users/dwelch/.codex/reports/duplicator-publication-ci-20261116`;
manifest SHA256 `2436e2a0b176368788a017c697cf28c99dde4137c96b1346d4b2e26f1fb1dce3`.
No PR is created. The module-container campaign remains open.

## wpDiscuz publication result

Checkpoint `93405d997925dd37cc50c39e9a180d946cfb38df` finishes with nine
successful workflows and one failed workflow: Meterpreter Acceptance.
All 64 checks are terminal: 62 succeed, one fails and one is skipped.
Both selected Ruby 3.3 jobs check out the exact fork commit and execute all
65 wpDiscuz contract examples successfully on their first attempt.

| Ruby 3.3 job | First attempt | Built-in retry |
| --- | --- | --- |
| [Normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43802744733/job/133086539690) | 19,694 examples, zero failures, 33 pending; seed 29446 | None needed |
| [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43802744733/job/133086539595) | 19,507 examples, zero failures, 664 pending; seed 17093 | None needed |

The eight-entry read-only unit seal is
`/Users/dwelch/.codex/reports/wpdiscuz-publication-unit33-20261116`;
manifest SHA256 `d7a671aef0cd66d813e7778008d4399723c04ed10d6607a9a81720d9ae293a17`.
Actual checkout is verified from each job's `git log -1` result, separately
from its workflow metadata. Content-tagged jobs also pass, but do not contain
the wpDiscuz contract group and are not its execution evidence.

The [macOS Mettle failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43802744970/job/133086541373)
has 46 examples and one failure, seed 29745. The failing path is
`osx/x64/meterpreter_reverse_https`, `post/test/cmd_exec`, with
`base64_transforms.profile`; its stderr-output assertion fails. The log does
not print the actual stderr value. Its actual Framework checkout is upstream
`bea1fb069e79cb610fe3981f16b8697790369c63`, also used by the earlier passing
macOS Mettle jobs recorded above. Cause and branch causality remain unverified;
no claim of a flaky test or wpDiscuz regression follows from these observations.
No agent retry or cancellation was initiated.

Selected successful native context jobs have Linux Mettle 51 examples and PHP
7.4 Linux 91 examples at that upstream checkout, and Linux command shell four
examples at the fork checkpoint. These general acceptance jobs do not execute
the wpDiscuz target profiles. Native binary/package-byte provenance was not
audited. The eleven-entry terminal CI seal is
`/Users/dwelch/.codex/reports/wpdiscuz-publication-terminal-20261116`;
manifest SHA256 `605089db8b14dd48b347852b78fa14d7f75a139ab6d45908e9bdd40e37f0b357`.
This follow-up changes no runtime qualification counts. The macOS stderr path
remains an investigation item. No PR is created.
