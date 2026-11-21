# ProjectSend failed-console recovery

Date: 2026-11-21. The opt-in session profiles now preserve the original console
transport error and terminate/reap that exact console before native fixture
recovery. This prevents further reset/session/job commands on a failed transport
and withholds dependent examples. Healthy-console behavior, module execution,
payloads, bounds and strict state assertions remain unchanged.

## Reproduction

```sh
bundle exec rspec spec/test/module_targets/projectsend_console_recovery_spec.rb
MODULE_TARGET_NAMESPACE=projectsend-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb projectsend_sessions projectsend_sessions_control projectsend_sessions_candidate
```

The last two profiles use explicit disposable baseline/candidate PHP source
overrides. They remain separate from the ordinary installed-payload profile;
see the [source comparison recipe](php_meterpreter_source/README.md).

## Recovery evidence

Eight focused transport cases use the actual acceptance console/driver and a
real Ruby child process. Together with seven shared support examples, identical
test inputs reproduce **15 examples / 6 failures** before the helper and pass
**15 / 0** afterward, without pending or outside-example errors. Durations are
11.70 and 6.48 seconds. These are process tests, not target emulation or module
qualification. They cover healthy commands/reset, timeout/error preservation,
partial-output capture, exact child termination/reaping, failed reset/close
idempotence, dependent-command rejection, genuine child exit, and an unrelated
host error that must leave a live console usable.

A separate real isolated msfconsole diagnostic runs an intentionally bounded
IRB sleep. It retains the original `Acceptance::ChildProcessRecvError`, kills
and reaps its exact child, then writes a fixture-recovery marker and verifies
reset/repeated close without extra transport requests. Recovery takes **1.52
seconds**. It invokes no module and creates no containers. An initial standalone
probe-loader failure omitted the Countdown require; that failed attempt is
retained separately. Earlier portable signal-status oracle corrections are
also retained, rather than counted as module failures.

The scoped helper saves `console-failure.json` before the standard after-example
log reset. Native recovery refuses to proceed if the failed console is still
alive. It does not change the generic acceptance console, driver or module-target
helpers. The three manifests declare the new helper and their previously
implicit acceptance-bootstrap/Countdown inputs.

## Fresh native results

Counts are examples/failures/pending. Every profile gets a fresh stack.

| Profile | Result | Outside-example errors | Seconds | Observed outcome |
| --- | --- | ---: | ---: | --- |
| Ordinary installed payload | 4/1/2 | 0 | 111.01 | Native CLI session readiness fails; owners withheld |
| Explicit baseline source | 4/1/2 | 1 | 124.33 | Native readiness fails; a callback socket also remains during cleanup |
| Explicit candidate source | 4/1/0 | 0 | 126.68 | Four sessions used/closed; strict deletion-permission preservation fails |

Installation, PHP/application identity, UID1000 callback and real reporting
database gates pass. The ordinary native CLI session does not become ready
within its bound. The baseline-source control retains an established UID1000
target callback socket while the console remains responsive; its readiness and
after-context cleanup assertions both remain visible. This is not the lost
console transport handled by this repair. Neither fresh baseline frame invokes
the owning exploit. Their exact live-wire causes remain unresolved.

The candidate proves native CLI/web sessions and two original default-owner
sessions, AutoCheck on/off and one selection, with physical proof, process and
callback identity, and original reporting-row closure. All four sessions are
used and closed. After each owner, `clients_can_delete_own_files` still changes
**1 to 0**; the full option-table expectation remains failing. Earlier five-row
prevention and valid registration behavior remain in place.

None of these fresh frames loses the foreground owner prompt. They therefore
do **not** establish native owner-timeout recovery; the controlled real-console
diagnostic and process regressions establish that recovery path separately.
The historical native owner timeout/cascade remains retained in the
[previous report](VERIFICATION-20261121-projectsend-registration.md).

## Integrity, cleanup and limits

The production module stays at SHA256
`2eba08bfb82a3ebcdca20aec942fef618e2edbdae9f1937529e69e599181f736`.
Both source overrides record their actual reader/generator and are removed.
Debug build remains false and debug logging unset. The installed payload 2.0.257
full manifest remains valid, and no repository payload fallback is present.
Human-written module Scenarios remain byte-identical at 926 bytes.

Thirty-six before/after cgroup captures are unchanged. OOM and PID-limit events
are zero; database memory.max is already 104, 109 and 108 respectively, so these
are not zero-pressure claims. At most three capped services run serially, with a
combined **768 MiB / 1.2 CPUs** limit. Each finished stack is immediately removed.
All **12 new / 747 recorded Docker objects** are independently absent; both Docker
contexts are empty, including stopped containers, and callback ports are closed.
The user's broader unused-container cleanup instruction finds no extra containers.

Changed Ruby lint and diff checks pass. The current declared input set is **416**;
the separately qualified set stays **132 passing cases / 37 profiles**, with
**49 ordinary** and **21 candidate-source** used/closed sessions. No new ordinary
session or wholly passing profile is promoted. Full module inventory, ordinary
payload readiness, remaining deletion/registration/security restoration and
r1295 runtime coverage remain unfinished. No PR is created.
