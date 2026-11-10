# Gogs new-repository rebase qualification

The integrated checkpoint is **178 runtime modules, 116 qualified families and
1,398 functional cases**. The new scope is Gogs 0.14.2 new-repository commands
at root and through `/gogs/`, plus Bash sessions at root. Existing-repository and
fixed-release profiles remain unqualified.

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gogs_hooks gogs_rebase gogs_rebase_existing gogs_rebase_fixed
```

## Actual results

Invocation `20261110T203229-977127` naturally exits one. All four profiles finish
with zero pending/outside errors, unchanged inputs and passing cleanup. Only
whole passing profiles contribute to the checkpoint:

| Profile | Cases/failures | RSpec seconds | Qualification |
| --- | ---: | ---: | --- |
| Hooks: 0.12.3 root and 0.14.3 subpath | 10/0 | 309.964833 | Requalified |
| 0.14.2 new repositories, root and subpath | 5/0 | 482.791015 | New scope |
| 0.14.2 existing repositories | 5/3 | 367.876596 | Unqualified |
| 0.14.3 fixed release | 5/1 | 221.089921 | Unqualified |

Each of the five new-repository cases completes both repetitions: ordinary-user
commands, used Bash sessions, repository-quota refusal, rejected credentials,
and commands through the real subpath. Exact marker/file bytes, UID1000, live
payload PID, explicit target exit and native PID absence are required. Supported
host shell closure follows remote proof; it is operator cleanup, not automatic
session deregistration. Hooks retain all ten cases and both calibrated delivery
families. The own/existing split retains every original rebase example body and
repetition, with complete native gates and the unchanged 600-second family bound.

Native CLI/HTTP/proof counts are respectively 73/327/22, 474/572/50,
474/572/50 and 150/231/19. All four native gates pass before owning assertions.
They establish real Git/UI operations, branch selection, identities, permissions,
quota behavior, actual token credentials versus stored digests, revocation and
scoped restoration. Real PostgreSQL queries verify the actual default workspace's
empty baseline, passive AutoCheck discovery, session-inferred vulnerabilities,
references, closed sessions and exploit-attempt links. Process stability requires
two equal pre-run identity projections within fifteen seconds; all raw processes
are retained without name filtering. Runner, dependencies, images and timeouts
are unchanged.

## Source repair and deferred observers

Separate production repair `acfeff19f8f` only registers required `TARGETURI` with
default `/`. The original module rejected the explicit subpath as an unknown
option. Capture-backed examples reproduce 4/2 before and 4/0 after; parent
verification passes eleven examples including seven ancillary examples,
two-file RuboCop and module msftidy. Root-default and explicit-subpath functional
repetitions now pass. The hooks owner is unchanged.

The original-owner baseline remains intact: rebase 10/8 and fixed 5/5. Its fixed
cases stopped at a native permission-oracle error before any module call. Old
reporting-count, unset-workspace and process-observer gaps are not retrospectively
treated as passing coverage.

Three new existing-repository failures stop at the added HTML observer. Actual
authenticated closed PR pages have `data-tab="request-"`; the observer requires
a numeric suffix. Actual index, exact active conversation link, closed state
and comment form are retained. Canonical pull-ref, seed-parent, feature-content
and no-extra-ref checks after that gate were not reached. Earlier successful
command/session operations do not waive failed repository-state verification.

The fixed missing-path test gets a genuine branded Gogs404. The module returns
Safe with `Gogs 0.14.3 detected, fixed in 0.14.3.` rather than the unrelated-product
reason the test expects. This is a test-oracle mismatch, not a vulnerable result.
The headers-only trace retains HTTP404 and the check result; its raw response
body is not archived, so the product fingerprint follows the unchanged check.
The other four cases pass, including repeated forced requests without a marker
or session, but the whole profile remains unqualified. Request-only vulnerability
reporting is kept separate from execution proof. Both observer corrections need
a fresh run.

Token warnings and native operator revocation remain separate from module
cleanup. Existing-repository iterations use fresh owned seeds; unchanged-repository
repeatability and removal of closed PR history, objects or merge caches are not
claimed. Other architectures/platforms and the complete existing/fixed profiles
remain pending.

## Parent verification and cleanup

The parent imports and byte-verifies all 277 invocation files, including failed
profiles, and verifies four current input maps of 60/57/59/57, union81. All 754
immutable export entries verify under
`/Users/dwelch/.codex/reports/gogs-rebase-module-validation-20261110-203229-977127/`;
the `CHECKSUMS.json` SHA256 is
`3690cb5916b25194beed18f49344c04c5fe5bf2b71410bd21cee2309becc5881`.
The separate source repair's verified 41-entry export is
`/Users/dwelch/.codex/reports/gogs-rebase-option-fix-20261110-1b5dfee0cc8/`,
manifest `6a5cb15f32578f924f793d659ed532f0edb326f7d524967722bc49e165a5dc21`.
The unused source-fix worktree is archived after that export.

One project runs at a time. Hooks use four containers/1,600MiB/2.2CPU;
own/existing five/1,728MiB/2.45CPU; fixed four/1,472MiB/1.95CPU. The parent checks
the live five-container limits and no OOM kill. The first real prompt, isolated
BOOT and two fresh parsed atomic metadata snapshots are observed live; subsequent
profiles use only normal within-invocation reuse.

After natural aggregate termination, the parent makes 52 fresh Docker queries:
all eighteen exact containers, four networks and seventeen volume names are
absent, twelve project-label inventories are empty, and global container
inventory is empty. No unrelated containers remain at that boundary. The broader
campaign remains active and incomplete.
