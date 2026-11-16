# Publication CI follow-up, 2026-11-16

## Planyo Ruby 3.3 follow-up

Both selected jobs check out the published Planyo commit
`6fa3bb29ed08df4e2577fca26645e6bf4f797122` and execute all 25 new file URL
contract examples successfully on their first attempt. The normal job reports
19,889 examples, zero failures and 33 pending; REMOTE_DB reports 19,702 examples,
zero failures and 664 pending. No retry is needed. These are the exact-checkout
[normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43850315404/job/133240843232)
and [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43850315404/job/133240843279)
jobs. This establishes selected unit execution, not an overall native acceptance
verdict. At 11:07 UTC eight workflows succeed, Command Shell is active and
Meterpreter is queued. There is no agent retry or cancellation.

The five-entry read-only CI seal is
`/Users/dwelch/.codex/reports/planyo-publication-unit33-20261116`;
manifest SHA256 `b382571fe8259ecd375ae663c19038deb6c77bbeefe6ee49d3c009564164db84`.

The terminal 11:47 UTC snapshot has nine successful workflows and one failure:
Meterpreter Acceptance. Its matrix has 22 successful jobs, one failure and one
skip. The [PHP 5.3 macOS job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43850315508/job/133240844563)
reports 91 examples and one failed example, seed 33470. That example opens a
stageless PHP reverse TCP session and runs `post/test/socket_channels`; its
aggregated failures are the UDP peer-information assertion and
`IO::EAGAINWaitReadable: recvfrom(2) would block`.

The actual Framework checkout is upstream
`bea1fb069e79cb610fe3981f16b8697790369c63`. The underlying UDP cause and
base-versus-fork causality remain unverified; payload/package source bytes were
not audited. The fork's Planyo changes were executed by the selected passing
unit jobs above. There is no agent retry or cancellation. The seven-entry
read-only terminal seal is
`/Users/dwelch/.codex/reports/planyo-publication-terminal-ci-20261116`;
manifest SHA256 `b91b784f054c4ff5027ca8c6fde044127dcb462942b74992aa8400a14ffc276d`.

## Photo Gallery terminal native follow-up

The Photo Gallery checkpoint `c45301644211c52741e342a42d1c39fc28a2312a`
finishes with nine successful workflows and Meterpreter Acceptance cancelled.
Its final matrix has 21 successful jobs, two cancelled and one skipped.
Check-run annotations establish that both cancelled jobs exceeded the configured
one-hour execution limit. They are
[Python 3.8 on macOS](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43842501043/job/133214394117)
and [Linux Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43842501043/job/133214394227).
The time limit explains cancellation; the underlying slow or stalled execution
remains unverified. No completed RSpec total is available for either job.

The Linux Mettle log checks out upstream Framework
`bea1fb069e79cb610fe3981f16b8697790369c63`. Its last observed activity opens
session 23 for reverse HTTP with `minimal_uris_headers.profile` and selects
`post/test/cmd_exec`; no further output precedes cancellation. The macOS log
retrieval returns HTTP 404 for the stored blob, which is retained alongside
the job metadata and timeout annotation. Its actual checkout cannot be
established from the missing log. No candidate module regression or intermittent
failure classification is inferred. There is no agent retry or cancellation.

The nine-entry read-only terminal seal is
`/Users/dwelch/.codex/reports/photo-gallery-publication-terminal-ci-20261116`;
manifest SHA256 `bf700dbb930d641b989b620bf7180ebee0c29a9bae8236bf689e87b01fccad8b`.

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

## File Manager publication e96bc7ac175

Observed 2026-11-16T07:26:02.153641+00:00. Both selected Ruby 3.3 non-content jobs checked out the exact published fork commit `e96bc7ac175e21df2f1c8a98048e7d2e9132f10d` and ran all 39 `WordPress File Manager elFinder replies` examples on the first attempt, with zero failures. This proves execution of the focused spec; it does not replay the Docker lab in hosted CI.

- [Normal job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43819702152/job/133139709528): first attempt 19,733 examples, 10 failures, 33 pending, seed 25461. The built-in retry ran 17 examples with zero failures, seed 23040. All ten original failures belong to the real HTTP Fetch lifecycle spec; none belongs to File Manager.
- [REMOTE_DB job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43819702152/job/133139709523): 19,546 examples, zero failures, 664 pending, seed 33272; no retry needed.

The Fetch failures are reproduced by loading the suite's WebMock RSpec bridge with unstubbed connections denied: 17 focused examples produce ten failures. The retry omits that bridge-loading path. A scoped spec repair permits only the current example's real HTTP/HTTPS `127.0.0.1` listener port and delegates all other policy decisions to the original method. It changes no library behavior or original lifecycle assertion. The identical denied-policy suite passes 17/0 after repair; selective existing policy and plain loading also pass 17/0 each. Intercepted runs observe 20 actual responses (12 HTTP, eight HTTPS; 16 status 200, four 404), zero response stubs and restoration of the original method/configuration after every example. Other ports, TEST-NET addresses and similar hostnames retain their original policy. Syntax, strict RuboCop and whitespace checks pass.

Worker commit `124ee17efee64ddb01e311134c046c228bce939c` was imported as `25d2b39763b`. The local immutable `fetch-lifecycle-webmock-policy-20261116` evidence archive has 4,710 entries; SHA-256 of `SHA256SUMS` is `d2a74baa2c19a22947fc77373de97c91f725e67b4397522a4567e48fdec8ac5e`. Parent verification rehashed every entry and confirmed the exact file set. This local repair remains unpublished at this observation. Full-suite CI for it has not yet run.

Nine workflows on the File Manager publication have completed successfully. Meterpreter Acceptance remains active at this observation, so overall publication CI is still pending. No manual retry, cancellation or PR was created.

### File Manager terminal observation

Observed 2026-11-16T08:13:15.810729+00:00: all ten workflows completed successfully; 63 checks succeeded and one was skipped. The initial normal-suite Fetch failures and built-in retry remain as recorded above. The scoped repair is now published in `28eb1a807b727e20a6690f78d5ab417811f7795b`; that publication's new CI is in progress.

[macOS Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43819702157/job/133139710490) passed 46 examples with zero failures; [macOS Java 21](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43819702157/job/133139710337) passed 51 with zero failures. Both logs show actual Framework checkout `bea1fb069e79cb610fe3981f16b8697790369c63`, the upstream revision selected by those general acceptance workflows. These results do not establish candidate payload-package byte provenance. The preceding publication's Mettle stderr failure remains unexplained; this passing run does not establish its cause. No manual retry or cancellation was performed.


## Depicter publication 28eb1a807b7

All ten workflows are terminal: nine succeed and Meterpreter Acceptance fails.
The 64 checks comprise 61 successes, two failures and one skip. Both selected
Ruby 3.3 non-content jobs check out the exact published fork commit
`28eb1a807b727e20a6690f78d5ab417811f7795b`. Each executes all 49 Depicter,
ten Fetch lifecycle and 39 File Manager contracts successfully on the first
attempt. These jobs do not replay the Docker profiles.

| Ruby 3.3 job | First attempt | Built-in retry |
| --- | --- | --- |
| [Normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43828175724/job/133166846856) | 19,782 examples, zero failures, 33 pending | None |
| [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43828175724/job/133166846775) | 19,595 examples, zero failures, 664 pending | None |

The two failed macOS jobs both show actual Framework checkout
`bea1fb069e79cb610fe3981f16b8697790369c63`, the upstream revision selected by
the general acceptance workflow. [PHP 5.3](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43828176646/job/133166852284)
reports 91 examples and 91 failures, seed 59407. All fail in shared console
startup before sessions: the process remains alive but its prompt never matches,
and the captured buffer contains only the OPENSSL_CONF legacy-functions notice.
That notice does not establish the startup cause.

[macOS Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43828176646/job/133166852328)
reports 46 examples and one failure, seed 14431. The reverse-TCP
`post/test/cmd_exec` path fails the double-quoted echo output assertion; the
actual mismatched value is not printed. Its stderr assertion passes. This
observation differs from the earlier reverse-HTTPS stderr failure and does not
resolve that investigation. Both current causes and branch causality remain
unverified. No agent retry or cancellation was initiated; candidate native
binary/package bytes were not audited.

The twelve-entry immutable CI seal is
`/Users/dwelch/.codex/reports/depicter-publication-terminal-20261116`;
SHA-256 of `SHA256SUMS` is
`8bd3cce615063cd215be2550486632e860ac124ec77ac47d7abcea27b6112ac0`.
The parent independently rehashed all twelve entries and confirmed the exact
file set. This follow-up changes no qualification counts. No PR is created.


## Photo Gallery publication c4530164421

Both selected Ruby 3.3 non-content jobs checked out exact fork commit
`c45301644211c52741e342a42d1c39fc28a2312a`. Their first-attempt output contains
all 45 Photo Gallery contracts, the new 37-case strict-results group, existing
31-case Common group, retained 49 Depicter contracts, ten Fetch lifecycle
contracts and 39 File Manager contracts. Every group has zero failures.
No built-in retry was needed and no agent retry/cancellation was initiated.
These hosted source suites do not replay the Docker targets.

| Ruby 3.3 job | Actual first-attempt result |
| --- | --- |
| [Normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43842500804/job/133214393004) | 19,864 examples, zero failures, 33 pending |
| [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43842500804/job/133214393003) | 19,677 examples, zero failures, 664 pending |

Actual checkout is verified from each log's `git log -1` result. Both separate
Common groups are counted (31 and 37), rather than inferring the new spec's
execution from a matching class name. The five-entry immutable unit CI seal is
`/Users/dwelch/.codex/reports/photo-gallery-publication-unit33-20261116`;
manifest SHA-256 is
`71da07bb6efde4f747e527d83b76b9908e7583ce6d67fa67248eaca88181af94`.
The parent independently rehashed every entry and confirmed the exact file set.
Other publication workflows remain pending at this observation. The earlier
upstream macOS startup/echo/stderr causes remain unverified. This follow-up
changes no coverage counts and is retained for the next module checkpoint.


A later Photo Gallery CI snapshot has nine successful workflows, including
Verify and Command Shell Acceptance. All ten Command Shell jobs succeed.
Meterpreter Acceptance remains in progress: seventeen jobs succeed, five
remain active and one is skipped. There is no overall terminal verdict yet;
no agent retry or cancellation was initiated.

## Drupal PostgreSQL publication result

Checkpoint `82729b27ecb47c509e65da8e28e527d6b6052ad4` passes both selected Ruby 3.3
unit jobs on their first attempt. Both actual checkout logs name that exact
published fork commit; no built-in retry is needed.

| Ruby 3.3 job | First attempt | Seed |
| --- | --- | --- |
| [Normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43864689481/job/133290115221) | 19,889 examples, zero failures, 33 pending | 20139 |
| [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43864689481/job/133290115343) | 19,702 examples, zero failures, 664 pending | 39152 |

The five-entry read-only unit CI seal is
`/Users/dwelch/.codex/reports/drupal-pgsql-publication-unit33-20261116`,
manifest SHA256 `4d23f5d9ddd81ad8e0fbe23b1042a3d3150fee0550db9f9c8dbc75ccf7f47aaf`.
These are unit results; they do not claim execution of the local Docker
functional profiles in those jobs.

The 2026-11-16 13:42 UTC workflow snapshot still has nine successful workflows
and Meterpreter Acceptance in progress. Its latest job snapshot has 22 completed
successful/skipped jobs and the macOS Mettle job still running. This is not an
overall terminal verdict. There is no agent-initiated retry or cancellation.


## Elasticsearch memory selected unit result

Published checkpoint `73255f3f2c9f9749ba84b14d10b934afad5a8745` passes all
fourteen Verify jobs on attempt two. Attempt one failed before RSpec while
Bundler copied a cached LicenseFinder Git repository: its commit-graph lockfile
was absent. The underlying missing-lock cause remains unverified. Matrix
fail-fast cancelled the other unit jobs. One complete Verify retry was requested
after that workflow became terminal; that retry budget is now used.

Both selected Ruby 3.3 logs independently show the exact published checkout,
all 25 Elasticsearch memory contract examples and one RSpec process with zero
failures. No example-level rerun was needed in either selected retry job.

| Ruby 3.3 job | Attempt-two result | Seed |
| --- | --- | ---: |
| [Normal](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43879140149/job/133346875945) | 19,914 examples, zero failures, 33 pending | 10442 |
| [REMOTE_DB](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43879140149/job/133346876081) | 19,727 examples, zero failures, 664 pending | 13540 |

The independently rehashed eight-entry unit CI seal is
`/Users/dwelch/.codex/reports/elasticsearch-memory-publication-unit33-20261116`;
manifest SHA256 `0691048757411c2ee9b3b6849e59f141dc76b6421a9b2451302f3066f9a48e67`.
The native acceptance workflow has separate execution provenance and results;
these unit results do not establish a native acceptance pass.

## Drupal PostgreSQL terminal native follow-up

The [Meterpreter workflow](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43864689557)
is terminal with failure; Generate report completes successfully. The
[macOS Mettle job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43864689557/job/133290117516)
reports 46 examples and two failures, seed 2225. An `osx/x64/meterpreter_reverse_http`
session opens using `base64_transforms.profile`; network-interface assertions
fail in `post/test/meterpreter`, followed by a completion timeout while the
console remains alive. The following `post/test/file` example cannot obtain
the prompt and retains the preceding test's buffer. An independent file-module
defect is not established.

That job's actual Framework checkout is upstream
`bea1fb069e79cb610fe3981f16b8697790369c63`, rather than the fork's Drupal
checkpoint. The underlying interface/stall cause, package source bytes and
base-versus-fork causality remain unverified. There is no agent retry or
cancellation. The six-entry terminal follow-up seal is
`/Users/dwelch/.codex/reports/drupal-pgsql-publication-meterpreter-20261116`;
manifest SHA256 `bdd28a6cda0aae201b31ed41b5f189fb25745cb26a0849fc4379674cd118e491`.


## Elasticsearch memory terminal native result

All ten workflows are terminal: nine succeed and Meterpreter Acceptance fails.
The Meterpreter matrix has 22 successful jobs, one failure and one skip;
Generate report succeeds. The [Java 21 macOS job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43879140453/job/133340018988)
passes all 51 examples with zero failures, seed 32835. Its `Archive results`
step then fails because ArtifactService/CreateArtifact times out after five
action-internal attempts. The underlying artifact-service cause remains
unverified. These internal upload attempts are distinct from the one complete
Verify retry recorded above; no native job retry or cancellation is requested.

The Java job actually checks out `rapid7/metasploit-framework` at
`aa9ce416588a2d6fb97423d23591089aff2c8c3e`. That is separate from the fork
checkout exercised by the selected Ruby unit jobs. Package source bytes were
not audited. The eight-entry terminal seal is
`/Users/dwelch/.codex/reports/elasticsearch-memory-publication-terminal-20261116`;
manifest SHA256 `386993b19aa49328297b8c28c5477d7ad3d4711c7e17b0b70e4e0910432daea8`.
