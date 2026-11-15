# Published WPS checkpoint: terminal CI

All ten workflows for published commit
[`f35fb9d3c4e6b2601cd459252851b6a06d788cce`](https://github.com/dwelch-r7/metasploit-framework/commit/f35fb9d3c4e6b2601cd459252851b6a06d788cce)
succeed. Of 64 check runs, **63 pass and one is skipped**. No workflow retry,
cancellation or PR was requested by this campaign.

The [Ruby 3.3 noncontent job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43735892695/job/132878295851)
checks out the exact published fork commit and reports **19,387 examples, zero
failures and 33 pending**. Its logged filters exclude acceptance and content.
This confirms the ordinary unit-suite result for that source. It does not add
local functional cases or replace the actual [WPS qualification](VERIFICATION-20261115-wps-hide-login.md)
and [native PHP contracts](VERIFICATION-20261115-php-reverse-native.md). No full
local RSpec suite was run.

Both native Mettle jobs check out upstream `rapid7/metasploit-framework` at
`bea1fb069e79cb610fe3981f16b8697790369c63`, as their actual checkout logs show.
Their workflow association with the fork does not make these branch-source tests.

| Native job | Actual result | Seed |
| --- | --- | ---: |
| [Linux Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43735892781/job/132878296392) | 51 examples, zero failures | 11552 |
| [macOS Mettle](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43735892781/job/132878296525) | 46 examples, zero failures | 8412 |

Native binary provenance was not separately audited here, and no new module
qualification is counted from these jobs. The [preceding publication's two
one-hour cancellations](VERIFICATION-20261115-php-publication.md) remain distinct
observations with an unverified initiating cause. These later successful runs
do not diagnose or erase those earlier results. Subsequent POST SMTP source and
fixture work is outside this published commit and this CI result.
