# Flowise recovery, sessions and fixed releases

The integrated checkpoint is **182 runtime modules, 124 qualified families and
1,420 functional cases**. All six selected Flowise profiles pass against current
inputs. This adds two modules, four families and eight cases to the preceding
[open/Basic checkpoint](VERIFICATION-20261110-flowise-open-basic.md).

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb flowise_300 flowise_basic flowise_305 flowise_306 flowise_311 flowise_312
```

## Actual results

Invocation `20261111T004528-83ba92` runs at frozen worker revision
`edbba171de8e3d769289e095d052d979853aca9a` and naturally exits zero. All six
profiles have exact expected counts, zero failures, pending or outside-example
errors, current inputs and passing teardown:

| Profile | Cases/failures | RSpec seconds | Selected coverage |
| --- | ---: | ---: | --- |
| 3.0.0 open | 3/0 | 137.668844 | Quiet commands, JS fetch/Meterpreter, unrelated paths |
| 3.0.0 Basic | 1/0 | 77.015970 | Commands and wrong/missing credentials |
| 3.0.5 JWT/recovery | 3/0 | 108.975268 | JWT execution, takeover/recovery, nonexistent victim |
| 3.0.6 fixed JS/reset | 2/0 | 70.226143 | Fixed-owner refusals and legitimate recovery |
| 3.1.1 npx/reporting | 2/0 | 152.026370 | Used Python shells, archives, reporting and auth refusals |
| 3.1.2 fixed npx | 1/0 | 47.378288 | Genuine SDK control, fixed check and forced refusal |

The durations exclude image/service setup and capture/teardown. Meaningful
operations repeat within these cases. The actual account takeover produces one
exact JSON credential loot file per iteration, accepts the changed password,
refuses the original password, rejects the consumed token and restores the
original password through genuine delivered recovery mail. Both iterations and
their restoration gates complete. The fixed release refuses disclosure while
ordinary login and mail recovery continue to work.

Consumed-token refusal requires the exact captured transaction-not-started HTTP 500,
a distinct replay password, complete actual read-only SQLite account/token row
equality immediately before/after replay, a fresh current-password HTTP 200 and
replay-password HTTP 401. An HTTP 500 alone cannot pass. Native recovery and owner-token
replay use this same strong proof.

Six owning sessions are opened and used: two Meterpreters each on 3.0.0/3.0.5,
and two npx Python shells on 3.1.1. Exact file bytes, actual UID/PID and ancestry,
remote exit and process absence remain required. Shell readiness now requires
the exact opened event before first use, matching independent calibration.
Supported host shell closure occurs only after remote ancestry absence. Three
independent native handler/payload calibrations are separate setup evidence.
The npx cases retain exact served archive/payload/request and resource removal
checks. Fixed 3.1.2 first proves a real installed SDK tool/PID/self-status response;
an empty action list cannot establish correct setup.

## Fixture corrections and preserved failures

Production owners, shared libraries/runner and existing human Scenarios are
unchanged. Fixture corrections retain every substantive assertion:

- Public entrypoint/manifest resolution handles private package exports while
  keeping original publisher name, version and byte hashes.
- Complete prior mail prefixes travel through stdin. Exact prefix/suffix,
  subject, deadline and backoff checks remain. Both real 220,472-byte argument
  failures are preserved; eight host file/pipe checks precede the genuine rerun.
- Shell use waits for bootstrap's opened event. Remote proof precedes explicit
  host closure; repeats and final registry/resource checks remain.

The earlier 4e mixed run remains in its 483-entry export. The later 2546 mixed run
retains 3/0,1/0,3/1,2/1,1/1,1/1 and natural exit one in its 557-entry export.
It observes 11 of 12 planned cases because the 3.1.1 failure stops its remaining
case. Actual mail-argument limits, command-before-opened timing and the second
private-manifest lookup are retained; none is rewritten as a production defect
or retroactively reported as passing.

Both current actual recovery messages prove authenticated TLS1.3 transport.
The profiles explicitly use **unverified local SMTP TLS**. The earlier strict
certificate failure remains preserved; trusted SMTP certificates are not
qualified and global Node TLS settings are unchanged.

## Evidence, resource control and review

The parent copies and byte-verifies the complete 475-file invocation, including
eight hidden/cache files, and independently verifies all 102 current inputs.
All 599 immutable export entries verify at
`/Users/dwelch/.codex/reports/flowise-six-passed-20261111-edbba171de8/`, manifest
`1c8582c4ae1e03b88359099aba44ac0a52e41a556cf8da339a45efa1d0289fc0`.
Raw controls, account/session/mail audits, actual natural termination, source
maps and parent cold/resource/terminal receipts remain together.

The parent observes the genuine first prompt and matching isolated BOOT live,
with two fresh stable parsed atomic metadata snapshots, no first-profile seed
and normal later-family reuse. Only one project runs at a time: three or four
containers, 1,888–2,144 MiB and 2–2.15 CPUs. After natural termination, 61 fresh
queries prove all 22 exact containers, 12 networks and 8 volumes absent, all 18
project-label inventories empty and global container inventory empty. Images
and unrelated volumes are preserved.

**Summary:** Current selected Flowise behavior passes 12/0. **What looks good:**
Forty focused fixture-unit examples, eight actual-capture pipe checks and Ruby,
Node/Python syntax/lint support the real functional evidence. **Concerns:**
Exact 3.0.1, Windows, application HTTPS, other roles/branches/payloads and the
model-dependent CSV-agent owner remain unqualified individually. **Suggestions:**
Measure those genuine prerequisites before extending coverage; keep failure
classification and restoration gates. The broader campaign remains incomplete.
