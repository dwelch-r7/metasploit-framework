# BookingPress publication CI follow-up, 2026-11-16

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

These jobs report successful conclusions, including their artifact stages.
Their workflow metadata names the fork checkpoint, but their actual Framework
checkout is upstream. Binary source and package provenance were not audited;
these results do not add runtime qualification for the fork's module changes.
The eight-entry read-only context seal is
`/Users/dwelch/.codex/reports/bookingpress-publication-native-context-ci-20261116`;
manifest SHA256 `55a445fd05d8e759d36c4b2d091dc879ffbe2ee2167ea65f2e278cbeee6ebadf`.

## Snapshot and remaining work

As of **2026-11-16 01:27:19 UTC**, the checkpoint has
61 successful checks, 1 skipped checks,
0 failed checks and 1 check still running.
The remaining native matrix job is
[Python 3.8 on macOS](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43781310242/job/133018896277).
This is a dated partial snapshot; the workflow is still being followed to its
actual terminal result. Later Duplicator commits need their own exact-head CI
observations. No PR is created.
