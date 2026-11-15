# POST SMTP publication CI checkpoint

Published head `c31abf19719cbb96e09078b6a38455bb9fc65803` is terminal:
**nine successful workflows and one cancelled workflow; 62 successful checks,
one skip and one cancellation**. This adds no module/profile/functional coverage.
The [local POST SMTP qualification](VERIFICATION-20261115-post-smtp.md) remains
separate from publication CI.

## Exact-source unit coverage

Both Ruby 3.3 non-content jobs actually check out
`dwelch-r7/metasploit-framework` at the exact published head. Their logs include
the new 37-example POST SMTP group.

| Configuration | Examples | Failures | Pending | Job |
| --- | ---: | ---: | ---: | --- |
| Default database | 19,439 | 0 | 33 | [132900792464](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43743237368/job/132900792464) |
| `REMOTE_DB=1` | 19,252 | 0 | 664 | [132900792375](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43743237368/job/132900792375) |

These are distinct configurations; counts and pending cases are not combined.
Functional container tests are qualified by the separate local recordings.

## Native acceptance and unresolved timeout

The [Linux native job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43743237435/job/132900793414)
is cancelled. GitHub explicitly records its one-hour execution limit. Acceptance
runs from 18:07:29 to 19:07:15 UTC. Its actual checkout is upstream
`rapid7/metasploit-framework` at `bea1fb069e79cb610fe3981f16b8697790369c63`.
Binary provenance is not separately audited. No matched before/after runtime
establishes attribution to campaign changes.

With seed 52524, `linux/x64/meterpreter_reverse_http` and
`base64_transforms.profile` establish a real session and pass binary, file and
ordinary directory controls. Creating the second directory in the symbolic-link
recursion test then times out after five minutes with `Rex::TimeoutError`.
Later file operations also time out. Two Railgun-labelled outer examples fail
to receive console prompts while retaining that earlier file-suite buffer. They
do not independently establish Railgun implementation defects.

The uploaded partial artifact contains 48 records: 45 passed and three broken.
There is **no final RSpec summary**; those partial counts are not a completed
suite result. The underlying transport failure remains unresolved. No retry,
cancellation or timeout increase was dispatched by this agent.

The [macOS native job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43743237435/job/132900793432)
passes 46 examples, zero failures, seed 53024, at the same upstream checkout.
That pass does not diagnose the Linux failure or qualify this fork's source.
The [Meterpreter workflow](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43743237435)
finishes cancelled after its report job completes successfully.

## Retained evidence

The read-only local export `post-smtp-native-ci-timeout-20261115` contains 405
independently rehashed entries: official job logs/annotations, partial native
artifact, failure sequence, exact-source unit logs and the earlier pending
aggregate snapshot. Its manifest SHA-256 is
`b3572aaf93c0802f71c91899bf9c41b0686b90cfc5a1a1e7af2c2db25f65d7cd`.
The terminal metadata is retained separately; the earlier seal stays unchanged.

The DukaPress and GI-Media publication heads remain under separate CI follow-up.
Their ongoing outcomes do not replace this checkpoint or earlier native
investigations. No PR is created.
