# Published PHP consumer checkpoint: terminal CI

All ten workflow runs for published commit
[`ad7bcf6721abedbdc2c4d63fbabdc2cf68c6107a`](https://github.com/dwelch-r7/metasploit-framework/commit/ad7bcf6721abedbdc2c4d63fbabdc2cf68c6107a)
are terminal. Of 64 check runs, **61 pass, one is skipped and two are cancelled**.
Nine workflows succeed; Meterpreter Acceptance concludes cancelled. No retry,
workflow cancellation or PR was requested by this campaign.

## Exact checkout and scope

The [Ruby 3.3 noncontent job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43726738183/job/132850194898)
checks out `dwelch-r7/metasploit-framework` at the exact published commit. It
reports **19,348 examples, zero failures and 33 pending**. Its logged filters
exclude acceptance and content examples. This establishes the ordinary unit
suite result for the published source; it adds no functional qualification and
does not replace the actual local WordPress/Drupal runs. No full local RSpec
suite was run.

Both cancelled native jobs instead check out `rapid7/metasploit-framework` at
`bea1fb069e79cb610fe3981f16b8697790369c63`. Their workflow run is associated with
the fork commit, but their tested Framework source is upstream. This distinction
is explicit in each checkout log and the reusable workflow's repository/ref
configuration.

| Native job | Actual outcome | Observed log evidence |
| --- | --- | --- |
| [macOS Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43726738371/job/132850195818) | Cancelled after one-hour maximum | Seed 3016; `osx/x64/meterpreter_reverse_https`, `base64_transforms.profile`, file-operation `Send timed out` messages and `Acceptance::ChildProcessTimeoutError` |
| [Linux Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43726738371/job/132850195913) | Cancelled after one-hour maximum | Seed 63733; `linux/x64/meterpreter_reverse_http`, `base64_transforms.profile`, file-operation `Send timed out` messages |

GitHub annotations explicitly state that each job exceeded its maximum execution
time of `1h0m0s`. That establishes the immediate cancellation reason. It does not
establish the initiating transport/payload defect. Neither interrupted suite has
a completed example summary, so completed example/failure totals remain null.
The initiating cause and native binary provenance are unverified. These runs do
not demonstrate a source regression from the published branch, since neither
executed that source. Earlier native CI failures retain their separate logs,
seeds and outcomes; they are not replaced by these observations.

The report-generation job succeeds after the two cancellations, and macOS Java
acceptance succeeds. Ordinary CI success, native upstream cancellations and the
local guarded functional qualifications are recorded separately. The subsequent
standalone PHP component and WPS Hide Login work are outside this published
commit and this CI result.
