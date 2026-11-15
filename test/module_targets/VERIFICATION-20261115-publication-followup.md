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
Other jobs were still running at inspection; this is not a terminal aggregate
CI verdict.

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

Commit `548d8368a71bd608204a4baa28403cd2fdd4dcba` still has queued and running
jobs. No terminal aggregate verdict or native exact-candidate provenance is
claimed here. Its local module-target qualification remains documented in the
[Simple Backup verification record](VERIFICATION-20261115-simple-backup.md).
