# Gogs repository qualification

The integrated checkpoint is **178 runtime modules, 118 qualified families and
1,408 functional cases**. All 25 Gogs cases pass against the corrected native
observers. This adds existing-repository and fixed-release qualification to the
[previous partial checkpoint](VERIFICATION-20261110-gogs-rebase.md).

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gogs_hooks gogs_rebase gogs_rebase_existing gogs_rebase_fixed
```

## Actual results

Invocation `20261110T212832-76d5bc` retains these complete per-family results,
zero pending/outside errors and passing teardown:

| Profile | Cases/failures | RSpec seconds |
| --- | ---: | ---: |
| Hooks: 0.12.3 root and 0.14.3 subpath | 10/0 | 313.880408 |
| 0.14.2 new repositories, root and subpath | 5/0 | 482.842818 |
| 0.14.2 existing repositories | 5/0 | 458.090342 |
| 0.14.3 fixed release | 5/0 | 218.747796 |

The aggregate summary is complete. Its original process handle was unavailable
after the goal continuation, so no directly observed aggregate exit code is
claimed. The four actual result/RSpec records and current inputs establish the
passing family results independently.

Commands require exact marker bytes. Eight owning sessions are opened and used,
with five separate native payload calibrations. Session proof requires a fresh
target-created file, UID1000, a live payload PID, explicit remote exit and native
PID absence before supported host shell closure. File contents and automatic
session deregistration are not claimed. New-repository commands cover root and
`/gogs/`; Bash sessions cover root. Each execution case repeats with a fresh
module instance against persistent targets. Existing-repository cases create a
fresh owned seed for each iteration.

All four native gates pass before owning assertions. CLI/HTTP/proof counts are
73/327/22, 474/572/50, 474/572/50 and 150/231/19. They establish real Git/UI
operations, identities, permissions, quota behavior, actual token credentials
versus stored digests, revocation and scoped restoration. Real PostgreSQL
queries verify the actual default workspace, typed services, passive AutoCheck
discovery, session-inferred vulnerabilities, references and exploit-attempt
links. Request-only vulnerability reporting remains separate from execution
proof. Two equal pre-run process identity projections are required within
fifteen seconds, with all raw processes retained.

## Corrected observers and retained failures

Only the native client and acceptance spec change after the partial checkpoint;
production owners, runner, dependencies, images, limits and Git-state assertions
stay unchanged. The separate one-option TARGETURI production repair remains as
documented in that earlier checkpoint.

The closed-PR observer now checks the actual rendered issue index, exact active
conversation link, comment POST form and reopen state. Genuine closed pages have
an empty `request-` tab suffix. Capture-backed offline checks pass three genuine
positives, 42 derived negatives and fifteen form/status comparisons. All six
actual repeated PR proofs then reach the original repository-state gates:
unchanged seed refs, exactly one canonical pull-head ref, its exact seed parent,
only the feature-file addition and retained original reachable objects. Added
logical objects are recorded before explicit owned-seed removal.

The fixed missing-path case independently captures the raw native GET404 body
and hash, exact route, Gogs author and release-validated CSS fingerprint. The
unchanged owner returns reason-bearing Safe for detected fixed 0.14.3. The test
requires the exact service graph and empty vulnerability/reference/session/
attempt/check state. Forced fixed-release attempts produce no command marker or
session. The earlier unrelated-product expectation was incorrect.

Original-owner and partial-checkpoint failures remain in their immutable exports.
They are not retrospectively counted as passes. Windows, other architectures,
same-instance state reset and repeated exploitation of an unchanged existing
repository remain unqualified. Token revocation and removal of owned seeds are
explicit native operator restoration; closed PR history, objects and merge
caches are not claimed to be automatically removed by the module.

## Evidence, resource limits and cleanup

The parent byte-verifies all 276 invocation files, including dotfiles and normal
metadata-cache reuse, and all current input maps of 60/57/59/57, union81. The
528-entry immutable export is
`/Users/dwelch/.codex/reports/gogs-repository-validation-20261110-76d5bc/`;
its `CHECKSUMS.json` SHA256 is
`d6b70b6b2a89d93a53f46f7aa9c29fdf1c1d45ba2f5c3ed483af940b9ccb33fa`.
It includes the complete invocation, selected inputs, observer readiness,
parent cold/import/cleanup receipts and lineage to the earlier failures.

One project runs at a time. Hooks use four containers/1,600MiB/2.2CPU;
new/existing repositories five/1,728MiB/2.45CPU; fixed four/1,472MiB/1.95CPU.
The first genuine prompt, isolated BOOT and two fresh parsed atomic metadata
snapshots are observed live without manual seeding. Later profiles use normal
within-invocation reuse. Service/console readiness stays 120 seconds and each
family stays 600 seconds.

After all four profiles finish, 52 fresh parent Docker queries verify eighteen
exact containers, four networks and seventeen volumes absent, twelve project
label inventories empty and global container inventory empty. Unrelated helper
containers are removed when observed; continuous global absence between
observations is not claimed. The broader campaign remains active and incomplete.
