# Integrated NFS and ActiveMQ reader checkpoint, November 10

Current input hashes, exact passing counts and owned teardown establish
**145 runtime modules, 73 families and 1,002 functional cases**. This adds two
[NFS/RPC scanners](VERIFICATION-20261110-nfs.md) and the genuine
[ActiveMQ source reader](VERIFICATION-20261110-activemq-disclosure.md) to the
retained [142-module checkpoint](VERIFICATION-20261110-capture.md). It also
includes a fresh [Flink replay](VERIFICATION-20261110-flink.md) after repairing
acceptance discovery. This selects qualifying retained runs; it is not a full
RSpec run or completion of the repository-wide campaign.

| Addition or replay | Functional cases | Failures | Current inputs |
| --- | ---: | ---: | ---: |
| NFS/RPC, integrated replay | 18 | 0 | 47 |
| ActiveMQ source reader | 8 | 0 | 43 |
| Flink read, discovery follow-up | 15 | 0 | 47 |
| Flink execution, discovery follow-up | 9 | 0 | 62 |

All four runs finish naturally, with no pending/outside-example errors and
successful teardown. The parent independently checks recorded input hashes and
exact-project resource absence. All 73 selected family results have the
manifest's expected count and current inputs. The registered WordPress admin
family has no qualifying result and is excluded. Its failures and the separate
Ansible deployer investigation remain in the [deferred index](DEFERRED.md).

The repository keeps reusable target components under `test/module_targets/`,
with per-family Compose, digest/source pins, independent native controls,
manifests, guides and acceptance specs under `spec/acceptance/module_targets/`.
Module documentation links to the relevant guide. The existing runner owns
projects, records native/console/reporting evidence and tears down only its
resources. Raw captures and historical exports stay outside Git.

Parent focused verification passes NFS 20/0 and reader 22/0; the reader count
includes seven shared formatter examples. Reader lint passes five Ruby files;
NFS preserves its one inherited optional-boolean-parameter offense. Changed
module documentation retains or clears the recorded existing diagnostics without
inventing human Scenarios. No full local RSpec suite was run.

The previous checkpoint's fork Verify run fails on Flink acceptance collection
with `KeyError: FLINK_TARGET_PROFILE`, before any examples. The parent reproduces
it, applies a one-line discovery default and verifies acceptance-excluded
collection (seven ancillary examples) plus explicitly selected 15/9 dry counts.
The fresh 24-case runtime replay above tests that integrated source. The prior CI
failure is retained; this checkpoint does not infer a green full suite from
target results. Subsequent fork CI must be inspected at its exact revision.

Parent receipts, complete new NFS/Flink invocations, original CI failure,
discovery comparisons, current selection and inventory are sealed at
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-21c67fa7d8d`.
All 215 checksum entries were re-read. `SHA256SUMS.json` SHA-256 is
`f55340756b7a5f3a452be3549ba444001797d0b8fc6357da004fb72527cc7b57`.
The family records link unchanged worker seals containing their native controls,
before/final results, source and cleanup. Historical seals are not rewritten.

The static inventory still has 5,179 source files, including payload components
and supporting code rather than only selectable runtime modules. It has 146
registered sources (145 qualified plus WordPress), 5,021 pending individual
reviews and 12 current source-hashed target reviews. Missing container hints
are not evidence of infeasibility. Additional database capture, FileServer, SIP
and Gitea qualification continue in separate worktrees. Other versions,
platforms, authentication paths and delivery families require their own evidence.
