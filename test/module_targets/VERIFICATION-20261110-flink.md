# Apache Flink module qualification, November 10

The `flink_read` and `flink_exec` profiles qualify two existing modules against
genuine Apache Flink 1.11.2 and 1.11.3 Linux images with their Java 8 runtimes.
The shared [target guide](flink_read/README.md) documents the pinned images,
native controls, credentials, coverage and limits. This is one addition to the
ongoing module campaign, not repository-wide completion or a full RSpec run.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb flink_read flink_exec
```

## Results and evidence

Final invocation `20261110T021350-885412` completed naturally:

| Profile | Cases | Failures | RSpec seconds | Current inputs |
| --- | ---: | ---: | ---: | ---: |
| `flink_read` | 15 | 0 | 66.291280 | 47 |
| `flink_exec` | 9 | 0 | 200.363381 | 62 |

Both profiles have zero pending examples or outside-example errors and passed
teardown. All 66 distinct recorded inputs match the integrated files. The parent
copied and byte-checked all 122 files in the complete invocation, retaining the
original revision, paths, commands and isolated metadata snapshots. Independent
exact-project inspection confirms both final projects' 16 containers and two
networks are absent; neither project used a named volume.

Eight loot files match native public/nested file bytes. Eight sessions were
opened and used: six staged Java Meterpreter sessions with the unchanged
default `Spawn=2`, and two inline Java command shells. Each positive execution
requires target identity/file proof and exact JAR, Java-process, added-file and
existing-job restoration. Two refused uploads retain their actual archives and
separate operator-restoration receipts.

The self-contained evidence export is
`/Users/dwelch/.codex/reports/flink-module-validation-20261110-4885ed88e236`.
The parent independently verified all 615 entries in `SHA256SUMS.json`; its SHA-256
is `7dd933ba03743849dc711e981e13ebd982fa721982e5f50c09df3b33aaa1925b`.
It contains the original and final invocations, frozen inputs, native commands,
failure diagnostics, payload archives, cleanup receipts and the two worker
patches. Raw evidence remains outside Git.

## Failure attribution and changes

The preserved original invocation `20261110T014940-f70837` returned raw read
15/0 and execution 9/4. Those counters were not accepted as qualification:

- Both modules consumed `TARGETURI` but warned that the setting was unknown.
  Registering their existing root-path default fixes the owning console-option
  contract. Identical real-module validator tests reproduce 6/2 before and 6/0
  after; the parent also passes all six examples without a database.
- Three default-payload cleanup failures were exited orphan JVMs retained by the
  vendor Java process running as container PID 1. Native captures show zombie
  state, no descriptors and empty command lines. Independent native comparisons
  establish that Docker init reaps them. The corrected fixture uses init, and
  final real payloads must still satisfy exact process equality; the observer
  does not filter zombies or override `Spawn`.
- Flink stages multipart JAR bytes before returning the disabled-submit 404.
  Fresh native uploads reproduce this with Flink's own WordCount JAR. The
  corrected rejection test captures and validates the actual generated archive,
  requires refusal/no session and explicitly records operator removal of staging.
  It does not claim automatic module cleanup through a disabled API.

Real JobManager/TaskManager pairs run both versions. Independent CLI/REST gates
verify versions, Java, UID 9999, file access/denial, patched traversal, shallow
depth and actual Apache Basic authentication. The execution gate runs six real
vendor WordCount jobs through root and authenticated-subpath routes, checks their
exact output/owner and removes native artifacts before module execution.

The source repair and target/test addition remain separate commits. Parent lint
passes both new Ruby test files. Changed module lint retains the same inherited
exploit RPORT registration offense; its existing msftidy diagnostic is disclosed
in the export. Both changed module guides pass documentation tidy and preserve
their human-written Scenarios. No shared runner, timeout, session or payload
implementation changed.

## Limits

This qualifies the specified Linux/Java 8 root and authenticated HTTP subpath
paths, repeated success/refusal, traversal boundaries and two Java delivery
families. It does not qualify Windows, Java 17, other Flink/Java versions, TLS or
client certificates, non-TCP handlers, optional payload modes or database
credential reporting. Disabled submission still requires the explicitly recorded
operator staging cleanup. The patched traversal release intentionally continues
to support normal JAR submission.

## Acceptance discovery follow-up

The fork's Verify run `42745125852` at checkpoint
`2e05634257939ee07a199fdf745af45a2a987308` fails during collection, before any
examples: the acceptance spec unconditionally fetches `FLINK_TARGET_PROFILE`.
The parent independently reproduces the same `KeyError` with acceptance excluded.
This is a test-discovery defect, not a target/module failure or a green CI result.

A separate one-line repair defaults discovery to `read`. Both manifests still
explicitly select their profile; no branch or functional assertion changes.
Acceptance-excluded discovery now passes seven ancillary examples with no
outside-example errors. Explicit dry discovery still selects 15 read and nine
execution cases. Spec lint is clean.

Fresh integrated invocation `20261110T034327-b208b4` requalifies the changed spec:
read **15/0 in 84.829864 seconds**, execution **9/0 in 212.775432 seconds**.
Both complete naturally, have zero pending/outside-example errors and pass
teardown. All 47/62 recorded inputs are current, with 66 distinct input paths.
Independent exact-label audits cover both original and new imported projects
per profile, with no remaining resources or recorded volumes. This replay has
its own actual prompt/BOOT and parsed atomic metadata receipts; prior evidence
is unchanged. The separate parent seal is linked from the
[new integrated checkpoint](VERIFICATION-20261110-nfs-reader.md). CI after the
next push must still be assessed at that exact new revision.
