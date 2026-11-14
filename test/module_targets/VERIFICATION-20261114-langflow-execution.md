# Langflow authenticated validation execution — 2026-11-14

All **ten functional examples and twenty public module calls pass**, including
four exact command proofs and six complete session lifecycles. The campaign
reaches **234 modules qualified in covered paths, 277 profiles and 2,649
functional examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_execution
```

The [lab](langflow_execution/README.md) qualifies
`exploit/multi/http/langflow_auth_rce_cve_2026_7873` against the genuine upstream
Linux amd64 Langflow 1.8.4 backend, with auto-login disabled and an explicitly
configured local account. Installed packages are Python 3.12.12, Langflow 1.8.4,
langflow-base 0.8.4, lfx 0.3.4 and MCP 1.26.0. Both validation source hashes and
the existing authentication/vendor record are checked. No target endpoint is
replaced, and no external AI provider is required.

## Source corrections and independent controls

The original owner executes its Python payload synchronously in validation.
A native socket callback held open independently prevented validation from
returning and caused a concurrent version request to time out. Releasing that
callback returned HTTP 200 with empty validation errors after 2.54 seconds;
the health endpoint then recovered. Separate native requests prove that benign
code works, anonymous validation receives 403, bad credentials receive 401,
and valid credentials permit both decorator and default-argument file writes.
Exact bytes and UID 1000 are verified, and those files are removed.

The first correction moves execution into a daemon thread and uses a function
default instead of a decorator returning `None`. This permits valid HTTP
responses while sessions remain active. Real shell lifecycles then pass, but
forked Python Meterpreter exposes another cleanup defect: the persistent parent
retains a duplicate callback socket and an unreaped child after shutdown.

The final owner runs the configured Python interpreter with an argument list
through `subprocess.run`, inside that daemon thread. It waits for and reaps its
launcher. Payload descriptors belong to a disposable interpreter. The existing
`MeterpreterTryToFork` option is preserved. With forking enabled, the detached
child is adopted and reaped by the target's normal init; this is verified with
the actual Docker init in this profile. With forking disabled, the waited
worker itself exits and is reaped. The backend stays responsive in both cases.

The [vendor advisory](https://www.ibm.com/support/pages/node/7278441) describes
the validation vulnerability and a broader affected range. This checkpoint
establishes actual behavior on 1.8.4; it does not infer other releases' behavior.

## Genuine functional results

Run `20261114T034233-2226b1` takes approximately **2 minutes 42 seconds**, including
a fresh cold console, native controls and teardown. The original controller,
manager and independent observer all exit zero. The observer directly checks
the live container caps and actual cold BOOT/prompt and fresh metadata.

| Covered behavior | Cases | Public calls |
| --- | ---: | ---: |
| Version classification, missing path, refused port | 3 | 6 |
| Bad credentials, AutoCheck enabled/disabled | 2 | 4 |
| Exact command execution, AutoCheck enabled/disabled | 2 | 4 |
| Python shell, forked and nonforked Python Meterpreter | 3 | 6 |

Every case repeats on the same selected console owner, without another `use`.
Positive commands produce four exact UID 1000 files, which are removed. All
six sessions reach the real ready event, execute remote operations, produce
exact file bytes, match exploit/payload database provenance and close their
database rows. A native version request succeeds while each session is open.
Both Meterpreter fork settings run twice; the fork-enabled case also runs
with AutoCheck disabled.

Shutdown takes a fresh remote response, closes the session and requires the
exact remote PID/birth identity to disappear. The complete original target
process set is restored after every case, with no extra live or defunct child,
callback connection, Framework job or session. The authenticated flow registry
is unchanged. All eight native probe invocations exit zero, and complete native
before/after results match. The final process oracle has no zombie allowance.

Three containers run serially: target 3,072 MiB/one CPU, Framework 768 MiB/one CPU
and reporting database 128 MiB/0.2 CPU. Swap equals memory limits, privileged
mode is disabled, and published ports bind to localhost. OOM, OOM-kill and
PID-limit counters remain zero. All **eight independent teardown queries**
pass for three exact container IDs, one network, project labels and the global
inventory. No application volume is created. Five subsequent global container
inventories are empty, and the shared heavy-lane lock is free.

## Verification and preserved failures

Four focused examples pass. Identical-spec before/after comparisons reproduce
the original blocking behavior and the intermediate inline-process behavior,
then verify the corrections. The final Python semantic probe uses a real held
loopback callback, separate PID/parent identity, daemon worker, transport EOF
and an already-reaped child on repeated execution. Its HTTP and payload doubles
and captured-validator model are explicit; the container cases supply the real
application and session evidence.

Strict Ruby lint, module tidy, documentation tidy, Python syntax and filtered
discovery pass. Filtered discovery runs seven shared content examples with no
lab environment and no load errors. No full RSpec suite is run. The human
guide's `## Scenarios` through EOF is unchanged, SHA-256
`c2a2762ee40544707a0d19ec473960931f373a38df31f996022634be94e4efa7`.

Source commits are `3e564ea6b99ff59e2926d4bbd98328fee2412ead` and
`e8133082dce6c2ad536a833b54eb5868c0d58135`; fixture commit is
`ed0cbc4210a3c23c24fe4d7eca0d2b706d152dd3`. All 53 selected input hashes match
the completed run. Final owner SHA-256 is
`8a504fc89a8301dc0510bfba64fd216ad94b299aba89720fec344cbc3c303445`.

The immutable archive
`/Users/dwelch/.codex/reports/langflow-rce-qualified-20261114` contains
**226 files and 53 selected inputs**, independently copied without hardlinks
and hash-verified. Its `MANIFEST.sha256` hash is
`10a9bdbfe2dc47a571198b05e1adae7177f05a8e09a2540fd7f6eb34ba6d22af`.

Earlier failures remain separately sealed:

- `langflow-rce-native-inventory-oracle-failure-20261114`: abbreviated versus
  full container IDs were compared before endpoint controls; no owner calls.
- `langflow-rce-functional-process-oracle-failure-20261114`: exact command
  execution worked, but an exited Popen child failed the original process
  assertion. Native controls separately reproduce its reaping behavior.
- `langflow-rce-functional-session-investigation-20261114`: the synchronous
  owner failed to finish shell bootstrap before its HTTP failure. The initial
  three-second session wait was also too short for Framework's roughly
  six-second bootstrap; the final session cases allow twelve seconds.
- `langflow-rce-functional-meterpreter-fork-failure-20261114`: the intermediate
  threaded owner proves a Meterpreter session but leaves the parent socket and
  forked zombie. Its 189-file archive manifest is
  `63f118de5d8d0f3635b2e30050f57a6647728a827d9cea67f61f6dae032c2852`.
- A native preflight refuses unrelated GitHub/AWS MCP server containers before
  creating any owned resource. Those containers are removed before retrying.
  An initial lightweight unit setup also omitted a normal Framework require;
  the corrected identical-spec comparisons and original failure are retained.

Each owned failed run completes teardown and an independent resource audit
before its selected inputs change. Native control successes, harness failures
and actual source failures are distinguished in their evidence.

## Self-review and remaining scope

**Summary:** Authenticated execution, both session families, Meterpreter fork
modes, repeat runs and cleanup qualify in this genuine configuration.

**What looks good:** Independent endpoint controls, real callback/session
proofs, live health, exact PID removal, database closure, strict original
process baseline, unchanged human Scenarios and bounded resource use.

**Concerns:** Other releases, architectures, operating systems, process
supervisors, TLS, URL prefixes, authentication providers and payload transports
remain unverified. Forked payload cleanup relies on normal target init reaping,
as exercised here. No additional material finding remains in the tested scope.

**Suggestions:** Calibrate the other Langflow owners separately before reusing
this target to qualify them. Inventory is 5,179 source files, 236 registered
owners, 269 pending documented container hints and zero stale reviews. The
standing `druid_js`, `freeswitch_batch`, `superset_rce_owner` and
`wordpress_admin` deferrals remain unchanged. The older remote Mettle
`post/test/file` timeout still has an unverified cause.
