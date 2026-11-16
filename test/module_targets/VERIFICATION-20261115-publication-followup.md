# Publication CI follow-up, 2026-11-15

This record concerns CI triggered by earlier module-target checkpoints. It adds
no local module qualification and does not diagnose the native timeout cause.
No workflow was rerun or cancelled for this inspection.

## GI-Media checkpoint

Trigger branch commit `cd26b4805fb3723ee3cd0b6a50fbbe4f7d4ed3e5` has a real
[Linux native failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43750627379/job/132923546837):
**51 examples, 1 failure**, seed 45236. The failing combination is
`linux/x64/meterpreter_reverse_https`, `base64_transforms.profile`,
`post/test/search`. Session 41 opens, then search setup reaches creation of
`meterpreter-test-dir-czbpivwh` without completing. The harness interrupts the
post module after its receive timeout; the console and generated native process
remain alive. The final RSpec exception is `ChildProcessRecvError`, caused by
`ChildProcessTimeoutError`. This job exits 1 rather than reaching the separate
one-hour cap recorded for the older POST SMTP checkpoint.

The actual Framework checkout in this job is upstream
`rapid7/metasploit-framework@bea1fb069e79cb610fe3981f16b8697790369c63`.
The triggering fork commit alone does not establish native candidate provenance.
The underlying runtime cause and installed native binary provenance remain
unresolved. Allure independently contains 51 result records: 50 passed, 1 broken.
This failure does not establish that the branch's GI-Media module or new module
tests caused it.

Raw job/API/log/Allure ZIP evidence is retained locally in the immutable
`gimedia-native-linux-search-failure-20261115` archive: 10 entries, manifest SHA256
`756e082b9e9a2927d6e4e5b3e2c6373cf203e4aa5e23fd766cad42b53e935a69`.
The final aggregate is **9 workflows succeeded, 1 failed**; its 64 checks comprise
61 success, 1 expected skip and the two native failures recorded here. Other
jobs were still running when the Linux evidence was first archived. The final
five-entry terminal supplement has manifest SHA256
`ed6c4e288fc9965f5e55c381323aaf75ab5ee0c0936e2162c06b05a5b1e686f6`.

A subsequent [macOS native failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43750627379/job/132923546776)
has **46 examples, 1 failure**, seed 39681. The failing combination is
`osx/x64/meterpreter_reverse_http`, `minimal_uris_headers.profile`,
`post/test/cmd_exec`. A command-response-after-sleep check fails with
`Rex::TimeoutError: Send timed out`; execution continues through later tests.
The other printed interface-check failures do not appear in the final RSpec
failure list. The actual checkout is the same upstream
revision above; the cause and installed binary provenance remain unresolved.
Its four-entry raw/API/assessment archive has manifest SHA256
`2b0dff6585858d5bb3cb6359063d0fc3944262bb8184f93b5c1e2109d4dfd3bb`.

## DukaPress checkpoint

Trigger `d00d1bf4c8af1e5cb73ac70332b9584ab3d90f94` is now terminal:
**10 workflows succeeded; 64 checks comprise 63 success and 1 expected skip**.
[Linux native](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43748516124/job/132917055149)
completed **51 examples, 0 failures**, seed 4885.
[macOS native](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43748516124/job/132917055033)
completed **46 examples, 0 failures**, seed 3899.
The completed-execution supplement contains 7 entries; manifest SHA256
`82b096dcc53b851f53850956fcaee5abf5e41bcda60096d2cf724a0e7cd3af3f`.
Both checked out the same upstream revision above; these are separate
runs rather than a retry or diagnosis of the GI-Media failure.

The terminal supplement contains 4 entries; manifest SHA256
`cc7224e6db7790e6865cfe9582219a085dae2cc62d389dd83c6ea2c97fc82e89`.

## Latest Simple Backup checkpoint

Commit `548d8368a71bd608204a4baa28403cd2fdd4dcba` is now terminal:
**9 workflows succeeded, 1 failed; 64 checks comprise 61 success, 1 expected skip
and 2 failures**.
The exact fork checkout's Ruby 3.3 unit jobs pass independently:
19,466 examples / 0 failures / 33 pending, seed 35683; and REMOTE_DB=1 with
19,279 examples / 0 failures / 664 pending, seed 54716. Both logs show the nine
new Simple Backup contract examples executing. These are separate filter/database
modes; their counts are not combined.

[PHP 5.3 on macOS](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43753505228/job/132932451415)
fails before tests: Ruby 3.4.12 Bundler setup exits 11 after GitHub port 443
connection failures cloning `rapid7/LicenseFinder`. The log records Bundler's
automatic retries; this inspection does not rerun the workflow. This job also
checks out upstream `bea1fb069e79cb610fe3981f16b8697790369c63`. No module executes
in that failed setup. Its four-entry raw/API/assessment archive has manifest
SHA256 `53d86cf0735a3998d4987db15c78c59b600f254a41942123c73e319044914530`.

[Linux native](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43753505228/job/132932451467)
finishes **51 examples, 1 failure**, seed 40008. The failing combination is
`linux/x64/meterpreter_reverse_https`, `minimal_uris_headers.profile`,
`post/test/meterpreter`. Process, system, network and earlier filesystem tests
pass. The copy-files check prints `Rex::TimeoutError: Send timed out`; the next
MD5/SHA1 upload starts before the outer receive timeout. The console remains
alive. The final exception is `ChildProcessRecvError`, caused by
`ChildProcessTimeoutError`. This differs from the GI-Media search setup stall;
the underlying cause remains unresolved. The actual checkout is the same
upstream revision above, and installed native binary provenance is unaudited.
Its six-entry raw/API/assessment/terminal archive has manifest SHA256
`572e275e6fb16b65fcf6231c7777535cce3e19fd8f8b7aa846a15ab27fd5eea4`.

Local module-target qualification remains documented in the
[Simple Backup verification record](VERIFICATION-20261115-simple-backup.md).

## Piwigo checkpoint

The exact fork checkout `ed79d0e1024542021817c9a1d5f3ce4daae116da` passes both
Ruby 3.3 non-content unit modes independently: **19,495 examples / 0 failures /
33 pending**, seed 57685; and REMOTE_DB=1 **19,308 examples / 0 failures /
664 pending**, seed 53981. Both logs execute all 29 new Piwigo credential
contract examples. These modes are not combined into one count. Their
three-entry log/assessment archive has manifest SHA256
`b3ddbb14326b0d364bd0eccf4bff5c8ea7196ea7ec404c3a71830af54b951606`.
The final aggregate is **10 workflows succeeded; 64 checks comprise 63 success
and 1 expected skip**. [Linux native](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43760382170/job/132953630184)
passes **51 / 0**, seed 58770; [macOS native](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43760382170/job/132953630106)
passes **46 / 0**, seed 29215. Both actual checkout commands resolve to upstream
`bea1fb069e79cb610fe3981f16b8697790369c63`; installed native binary provenance is
unaudited. These are separate runs, with no retry/cancellation performed here.
The seven-entry terminal log/API/assessment archive has manifest SHA256
`de5cea7b7d68772d7623d6cb536498ca911bf088c4df243d8b3ecdbad1e708d1`.

## Erlang SSH checkpoint

The exact fork checkout `614994d24526337b0896603202b61972a25693b4` passes both
Ruby 3.3 non-content unit modes independently:
[ordinary database mode](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43773721397/job/132995116238)
has **19,547 examples / 0 failures / 33 pending**, seed 3632; and
[REMOTE_DB=1](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43773721397/job/132995116406)
has **19,360 examples / 0 failures / 664 pending**, seed 28939. Actual checkout
log output identifies that fork revision, and both logs execute all 52 new
Erlang SSH command/check contract examples. The modes are not combined.
The five-entry raw log/API/assessment archive has manifest SHA256
`85482b6452cb8646ec8cc3e00c43da795b9b67ea422f1a46eef8b6cbcb984c24`.

The terminal aggregate is **9 workflows succeeded, 1 failed; 64 checks comprise
62 success, 1 expected skip and 1 failure**. The failure is the post-test artifact
upload described below. No retry or cancellation is performed here.

The subsequent [Linux native result](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43773721551/job/132995118229)
passes **51 examples / 0 failures**, seed 56206. Its actual Framework checkout is
upstream `bea1fb069e79cb610fe3981f16b8697790369c63`, despite fork-head job metadata;
it does not establish native execution of the new fork source. Installed native
binary provenance is unaudited. Its three-entry raw/API/assessment archive has
manifest SHA256
`e42503d77b7172ebf1956e503eaefdf854a531e55cfab15f5e21a76160a8670c`.

[Python 3.11 on macOS](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43773721551/job/132995118124)
passes **91 examples / 0 failures**, seed 4002, then fails the `Archive results`
step. `actions/upload-artifact` times out creating the artifact after five
built-in attempts. This is a post-test artifact upload failure. The actual
Framework checkout is upstream `bea1fb069e79cb610fe3981f16b8697790369c63`; installed
payload provenance is unaudited. No agent retry or cancellation occurs. The
three-entry raw/API/assessment archive has manifest SHA256
`c10181f3ee93cf2bf93e8a2258f4e40dd7e98a243dba686795827cd1bbeac982`.

[macOS native](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43773721551/job/132995118236)
passes **46 examples / 0 failures**, seed 38643. Its actual Framework checkout is
also upstream `bea1fb069e79cb610fe3981f16b8697790369c63`; installed
native binary provenance remains unaudited. The six-entry terminal log/API/assessment
archive has manifest SHA256
`eea49518b9a78b834870c26d6f7e5b39068ebbe786872eb1ab7dafaf40733a48`.
