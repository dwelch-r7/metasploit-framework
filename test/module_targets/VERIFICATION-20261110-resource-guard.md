# Local resource guard

The optional `tools/dev/run_guarded_module_target_tests.rb` launcher limits
subsequent local campaign invocations to one guarded run across the user's
worktrees and at most five resolved containers per family. The lock remains held
through the original runner's teardown. Existing containers, malformed or
unbounded Compose plans, failed inventory and failed preceding cleanup refuse
startup. Refusals record `setup_resource_refused`, `module_verdict: null` and
`cleanup: not_started`; they do not classify module behavior or remove containers.

The original runner, SDK, timeout defaults and published target inputs are
unchanged. At guard integration the passing checkpoint was **173 runtime modules,
107 families and 1,359 functional cases**, with every selected count, input digest
and owned cleanup result checked again. The new launcher's SHA-256 is
`dc35fa946bdae20374e9345fe40dd67b5f3a6ce3b3919c22e41aff6482028899`;
guarded positive results also record that source as an input.

## Verification

- The focused guard spec passed **21 examples, zero failures, zero pending and
  zero errors outside examples** in 0.742 seconds in the parent worktree.
  It covers separate-process lock contention, interruption/cleanup and lock
  release, conservative scale/replica counting, malformed plans and inventory,
  subsequent-family refusal, and informational/invalid CLI requests. Docker
  commands in this spec are mocked.
- RuboCop inspected both new Ruby files with no offenses. The worker also
  verified syntax, identical `--list` output and guarded usage for invalid input.
- A real Docker/Compose preflight selected the historical `druid_jndi` profile
  with an empty container inventory. It resolved nine services including
  Framework and exited 1 with the expected five-container refusal. No target,
  build, console, RSpec or teardown command ran. The before/after inventories
  were empty and the user-scoped lock was independently reacquired afterward.
  This is a refusal-path check, not a new Druid functional run.
- A subsequent guarded Gogs invocation exercised actual four-container startup,
  test failure and teardown. The complete native target gate passed, then all
  ten examples inherited one Meterpreter calibration readiness failure before
  any Gogs module ran. The session was registered but was not confirmed fully
  initialized; its payload PID and graceful closure were unobserved. All nine
  owned objects were absent after teardown. The parent independently verified
  the four-service plan, all 55 unchanged inputs, empty Docker inventory and
  released lock. This verifies the guard's startup and failure lifecycle; it
  does not qualify Gogs or establish a module defect.
- The later repaired `gogs_hooks` family passed all ten functional examples
  through the guarded launcher. Its qualified scope and exact resource audit
  are recorded in the [Gogs checkpoint](VERIFICATION-20261110-gogs-hooks.md).

Parent evidence is retained in
`tmp/module-target-resource-guard-parent-rspec.json`,
`tmp/module-target-resource-guard-parent-rubocop.txt` and
`tmp/resource-guard-real-preflight-20261110T142814Z/RESULT.json`; the real
preflight's rendered plan and classified result are under
`tmp/module-target-tests/20261110T142816-47cc40/` as recorded by that receipt.
The Gogs lifecycle receipt is
`tmp/resource-guard-gogs-startup-parent-receipt.json`, referencing worker
invocation `20261110T143857-faa8d0` and its preserved cold-start/native evidence.
The worker exports are in
`/Users/dwelch/.codex/reports/module-target-resource-guard-20261110/` and
`/Users/dwelch/.codex/reports/module-target-resource-guard-usage-20261110/`.

## Limits

This is a cooperative same-user advisory lock, not Docker daemon isolation.
Native smoke launchers, manual Docker commands, other users and the original
runner need explicit serial coordination. Every resolved service counts at
least once, including disabled profiles and zero replicas; historical larger
profiles must be split before local replay. CPU/memory ceilings remain the
responsibility of each profile, and the guard does not count temporary build
internals or containers created inside a nested runtime. Those profiles need a
separate assessment before local replay.
These checks add no qualified modules or functional cases. The full
module qualification campaign remains incomplete.
