# wpDiscuz upload validation, 2026-11-16

All eight genuine profiles pass **33 functional cases and 66 public module
calls** with their expected success or refusal outcomes. The tests make 124
independent native HTTP requests, use 16 native and 16 owning sessions, and
verify 32 remote transport closures. The module removes all 16 session payload
files before operator attachment-metadata recovery. Ten non-session command
proofs explicitly use operator recovery.

This adds one runtime owner and eight profiles, reaching **259 owners in covered
paths, 401 profiles and 3,391 functional cases**. Earlier families retain their
recorded inputs and scope; this is not a whole-campaign replay of the current
checkout. The campaign remains open. No PR is created.

| Profile | Release / mode | Install prefix / uploads | Cases | Public calls | Native / owner sessions | Run |
| --- | --- | --- | --- | --- | --- | --- |
| `wpdiscuz` | 7.0.4 / affected | / / dated | 7 | 14 | 6 / 6 | `20261116T034614-e22bd7` |
| `wpdiscuz_minimum` | 7.0.0 / affected | / / dated | 4 | 8 | 2 / 2 | `20261116T034221-53a978` |
| `wpdiscuz_prefix` | 7.0.4 / affected | /wordpress / dated | 5 | 10 | 4 / 4 | `20261116T035207-bbebdb` |
| `wpdiscuz_custom` | 7.0.4 / affected | / / custom | 5 | 10 | 4 / 4 | `20261116T035207-bbebdb` |
| `wpdiscuz_guest_disabled` | 7.0.4 / guest_disabled | / / dated | 3 | 6 | 0 / 0 | `20261116T035207-bbebdb` |
| `wpdiscuz_fixed` | 7.0.5 / fixed | / / dated | 3 | 6 | 0 / 0 | `20261116T035207-bbebdb` |
| `wpdiscuz_absent` | absent / absent | / / dated | 3 | 6 | 0 / 0 | `20261116T035207-bbebdb` |
| `wpdiscuz_unrelated` | unrelated / unrelated | / / dated | 3 | 6 | 0 / 0 | `20261116T035207-bbebdb` |

## Genuine application and independent controls

Official checksum-pinned wpDiscuz 7.0.0, 7.0.4 and fixed 7.0.5 ZIPs run on pinned
WordPress 5.2.4 / PHP 7.3.11 with MariaDB 11.2.2. The
[release catalog](wpdiscuz/releases.json) records archive hashes and three
installed source hashes for each release. Vendor code is unchanged.
[Wordfence's original analysis](https://www.wordfence.com/blog/2020/07/critical-arbitrary-file-upload-vulnerability-patched-in-wpdiscuz-plugin/)
and the pinned affected/fixed source establish the affected range and patch.

Native requests inspect genuine public comment metadata for the actual ordinary
post, ID 4. They verify valid GIF bytes, invalid nonce and missing-post refusal,
PHP marker execution or denial, target identity and WordPress API cleanup.
Release 7.0.0 rejects the short GIF8 marker and accepts GIF89a; 7.0.4 accepts
both, while fixed 7.0.5 refuses both PHP uploads. The guest-disabled profile
still accepts an authenticated administrator's ordinary GIF, proving a working
backend while anonymous PHP uploads are refused. An absent readme produces an
Unknown check and guarded refusal; it is not treated as a known Safe version.

Before owner calls, real Framework handlers generate the selected payloads.
Their already-cached encoded PHP is uploaded through independent native HTTP
requests, preserving the real handler UUID/transport association. Each selected
payload is used twice through the public session API, with independent file
bytes, UID 33, process status and live callback evidence. Meterpreter exposes a
persistent PHP PID; the PHP shell's transient command status is captured before
that child exits. Remote shutdown, absent live callback sockets and empty
Framework session/job state are checked. Native HTTP execution requests finish.
Apache worker PIDs can persist normally.

Owner calls repeat the selected command, shell, single-stage Meterpreter and
staged Meterpreter paths listed in [profiles.json](wpdiscuz/profiles.json).
Default cases use the real console's `unset PAYLOAD`, verify the restored
module default and omit a PAYLOAD override. Actual session payload identities
are checked. AutoCheck-disabled commands, nonexistent BLOGPATH, fixed code,
guest-disabled uploads, absent plugins and unrelated HTTP are covered.
Recorded target snapshots agree before and after. Unrelated HTTP retains its
exact response hash. Session-file cleanup is verified before the operator
removes remaining WordPress attachment records. Non-session files and metadata
are explicitly recovered between repeated commands; no autonomous cleanup is
claimed for those cases. Email delivery is disabled and untested.

## Confirmed defects and preserved failed attempts

Original module SHA256 is
`c4356d591a8aff4209cd72817f9573dc67f0c93513f8a35c57fae4da22bee6e5`.
Three original public probes, six calls in total, independently establish:

- Hardcoded post ID 1 rejects the real post ID 4 with msgUploadingNotAllowed.
- The hardcoded dated execution URL returns 404 for a genuine custom non-dated
  upload, while independent requests execute that same file.
- The registered requested filename differs from the plugin's renamed file.
  The probe uses a non-session command; it proves incorrect registration, not an
  attempted session-cleanup failure. The existing ends_with? alias works in the
  actual console and is not reported as a defect.

After those fixes, a genuine minimum-release run first uses and remotely closes
two native default staged sessions. The owner checks twice, then its command
upload is refused: the original four-byte GIF8 prefix does not match 7.0.0's
GIF8[79]a content check. This fourth source defect is repaired with GIF89a,
without changing the declared minimum or the default payload.

The repaired module uses the selected post's nonce and ID, validates upload
reply shapes, executes the returned path/query over the configured transport,
and registers the actual renamed basename. The legacy nonce-array helper and
version discovery call remain compatible. The localized JSON scanner handles
nested objects, strings and escapes, including valid phrase text containing
braces and semicolons. Expected transport/reply failures have typed reasons.

Separate-worktree unit evidence retains all 65 final contracts: the initial
59-case original/fixed pair reports 36 failures then zero; six valid JSON phrase
cases expose and repair an introduced parser regression; the final GIF
signature comparison fails one independent protocol contract on fc46 and
passes all 65 on the repair. External boundaries remain doubled in those units;
the genuine Docker runs provide application and session qualification.
Preliminary invalid-fixture and 66-case lint attempts remain preserved.

Harness failures are distinguished from module defects: traced vendor changelog
text matched an Exception substring; provenance initially observed AutoCheck's
wrapper; native 7.0.0 behavior was initially overconstrained; a block-local
trigger was invisible to ensure; the console retained an earlier payload; and
raw datastore.to_h omitted effective defaults. Each attempt is retained with
actual terminal status and cleanup. The transient shell-PID observation was
corrected before final shell qualification. No failed attempt is counted as a
passing profile.

## Inputs, resources and checks

Runtime owner SHA256 is
`3e35f147abab9c9b64719b93a79244c38b6ba9f55d55ec9da2b0fc40c0507d9e`.
All eight passing profiles use tested revision
`bf91a26482157c5b0311a515bd727e86b2292bbe`; all declared inputs match the current
checkout. Final source repairs are imported as 4f3aa403a7d, 8805956b26d and
da8e8087a2a. The whole human module guide, including Scenarios, is byte-identical:
SHA256 `5d40e7e5e54a8e1c9669bb9e22ddeb319e5c0ad91e00a2469123b0f0c7059faf`.

All new fixture Ruby has zero lint offenses. Strict changed-file lint retains
only the existing module default-payload warning and eight unchanged SNMP spec
convention findings; there are no new offenses. Owner msftidy exits 2 solely
for that same preserved default warning. Syntax, discovery and diff checks pass.
The separate [publication follow-up](VERIFICATION-20261116-publication-followup.md)
records the SNMP test-isolation repair and exact prior CI attempt/retry and
checkout distinctions. No local full RSpec suite was run.

Every stack is serial and capped: WordPress 0.5 CPU / 384 MiB, database 0.5 CPU /
512 MiB and, for session profiles, Framework 1 CPU / 1024 MiB. The unrelated
service uses 0.25 CPU / 128 MiB. Memory equals swap limits; PID caps are 128,
with 256 for Framework; every service has init. Actual inspections agree.
Published ports bind to loopback, the database uses the internal network, and
recorded OOM/PID-limit counters are zero. At most three containers run together.
All eight final project/network/volume audits pass: 40 cleanup queries, plus
independent final global inventory and lock acquisition. Docker is empty.
Unrelated images and volumes are not pruned.

The final eight seals contain **1,008 rehashed entries**. The read-only checkpoint
`/Users/dwelch/.codex/reports/wpdiscuz-qualified-checkpoint-20261116`
has 35 entries and manifest SHA256
`d0526cbfff5dcb256e7ab992ccfee67322434feb2889641d563af8387791e4ae`.
Its index references 35 immutable archives; all 4,434 referenced entries were
independently rehashed, including native probes, original/failing attempts,
source repairs and related CI evidence.

Fresh inventory records 5,179 sources, 4,622 module candidates, 260 registered
sources, 4,339 pending candidates, 245 pending container-documentation hints,
26 individual reviews and zero stale reviews. Registration alone is not runtime
qualification. Other WordPress/PHP releases, Windows PHP, multisite, TLS,
intermediary deployments and payload/profile combinations not selected in the
matrix remain unqualified.

From the Framework root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/wpdiscuz/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wpdiscuz_minimum wpdiscuz wpdiscuz_prefix wpdiscuz_custom wpdiscuz_guest_disabled wpdiscuz_fixed wpdiscuz_absent wpdiscuz_unrelated
```

The [component guide](wpdiscuz/README.md) explains resources and recovery.

## Review

**Summary:** Four reproduced upload/execution/registration defects are repaired.

**What looks good:** Independent target and payload calibration precedes owner
classification; actual bytes, identity, default selection, file cleanup and
remote transport closure agree across the selected paths.

**Concerns:** The explicit platform/version and deployment limits above remain;
earlier campaign families retain their historical inputs.

**Suggestions:** Follow exact-head publication CI and continue the pending
module inventory. The broader goal remains active.
