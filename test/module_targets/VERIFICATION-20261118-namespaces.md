# Namespaced module target ownership, 2026-11-18

The guarded runner now accepts an explicit task namespace. Every resolved service
receives ownership/run labels, project names include the namespace plus a fresh
run ID, and startup checks only that namespace for lingering containers. Cleanup
remains scoped to the freshly created Compose project. Unlabelled containers and
containers belonging to other namespaces are preserved.

```sh
MODULE_TARGET_NAMESPACE=my-module-tests bundle exec ruby tools/dev/run_guarded_module_target_tests.rb bentoml_fixed
```

The namespace is restricted to 1-32 lowercase letters, digits and interior hyphens.
The constructor snapshots it so a caller's later string mutation cannot change
ownership during a run. All private helpers, including database and Framework
services, receive the same `org.metasploit.module-targets.namespace` label. Without
this option, the existing empty-inventory behavior is retained. The user-scoped
advisory lock and five-container resolved-plan limit remain in place. Neither
startup mode automatically removes an existing container.

## Verification

**53 focused guard/network cases pass**, with zero pending/outside errors and
zero scoped RuboCop offenses. Existing lock contention, default inventory refusal,
service/replica caps, malformed metadata and cleanup failure behavior remain
covered. New cases cover namespace filtering, labels on private helpers, startup/
cleanup project identity, owned leftovers, failed label resolution, invalid input
and immutable ownership identity.

The real Docker check creates a 16 MiB sleeping sentinel in a different namespace,
using this chat's existing pinned image and recording its ID and ownership labels.
It then runs the genuine patched BentoML profile under `mcv-01a1bcef`. Run
`20261118T124845-7ae483` passes **5/0**, including native before/after predictions and
pickle rejection. All four resource-event captures are zero. Docker inspection
confirms the actual target's ownership label and namespaced project name.

After the runner removes its own project, the sentinel remains running with its
name, labels and start time unchanged. The test then removes only that sentinel
by its recorded ID after checking this chat's ownership labels. The namespace
finishes with zero owned containers. **No unrelated container is stopped or
removed.** These are launcher regressions, with no new module/profile breadth
increment; totals remain 295 owners, 598 qualified profiles and 4,186 historical
functional cases.

The immutable capsule `module-target-namespace-20261118T124845-7ae483` contains 124
files, including 53-case results, native replies, the live controller, actual
container observations, 65 unchanged runtime inputs and exact source snapshots.
Its SHA256 manifest is `0883fe83836982274637da96306ee14b0597fb68843517c88bd07dcaf5e48528`.

Task-local legacy helpers that removed containers by a global inventory or MCP
image name are retired. Future native labs use explicit task-labelled projects
and cleanup only their own recorded objects. Source qualification continues;
no PR is created.
