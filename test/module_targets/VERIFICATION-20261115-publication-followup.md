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

Commit `548d8368a71bd608204a4baa28403cd2fdd4dcba` still has running jobs.
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

No terminal aggregate verdict or native exact-candidate provenance is claimed
here. Local module-target qualification remains documented in the
[Simple Backup verification record](VERIFICATION-20261115-simple-backup.md).
