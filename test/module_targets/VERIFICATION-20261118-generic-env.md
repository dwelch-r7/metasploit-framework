# Generic environment collection and Meterpreter repair, 2026-11-18

Qualified [post/multi/gather/env](../../modules/post/multi/gather/env.rb) with **six passing functional cases, CLI exit 0 and successful teardown**, reaching **289 runtime owners in covered paths, 584 qualified profiles and 4,068 historical functional cases**. Eight actual calls use six genuine sessions and persist eight raw environment files. Native, unit, baseline and replay controls are not added again. The broader campaign remains active; no PR is created.

## Reproduction and independent prerequisites

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb generic_env
```

The [target guide](generic_env/README.md) describes the opt-in profile. Digest-pinned Ubuntu 22.04 uses coreutils `8.32-4.1ubuntu1.4` and Python `3.10.6-1~22.04.1`; actual package versions and Linux/amd64 are observed. A real host Framework console uses an ordinary PostgreSQL reporting role with an initially empty schema. Target launchers clear inherited container environment and supply only controlled values: account/PATH/locale fields plus empty, spaced, equals-containing, UTF8 and multiline canaries. A large variant adds 65,536 bytes plus an end marker.

Native `/usr/bin/env -0` controls run under actual root and ordinary UIDs and compare complete fixture maps without newline ambiguity. A separate standalone cohort passes all four actor/size combinations, with selected state unchanged and its sole container/network removed. The functional profile runs the four controls before and after owning collection. Genuine Framework-generated command and ELF payloads produce actual shell/Meterpreter callbacks; source path/hash, OS actor/PID identity and each session process's initial environment are independently verified.

The shell uses `cmd/unix/reverse_bash`; its metadata reports Unix on the physical Linux target. Meterpreter uses `linux/x64/meterpreter_reverse_tcp` with forking disabled. The native launcher PID and actual session PID are recorded independently. No session, environment or reporting API is doubled in the functional profile.

Linux [`/proc/PID/environ`](https://www.man7.org/linux/man-pages/man5/proc_pid_environ.5.html) exposes initial execve values, not later environment updates. An independent actual Meterpreter getenv RPC therefore supplies current PATH/LANG and controlled values before owner execution. Controlled values must still match the initial native fixture. The pinned [upstream initialization reference](https://github.com/rapid7/mettle/blob/4dd76aed028fff0a214564cb4c389947b71a194b/mettle/src/process.c#L124) explains PATH/LANG setup, and its [getenv provider](https://github.com/rapid7/mettle/blob/4dd76aed028fff0a214564cb4c389947b71a194b/mettle/src/stdapi/sys/config.c#L39) reads current values. Exact agreement between that source revision and the bundled binary is not attested; the real session RPC remains the runtime authority.

## Confirmed defect and final-contract owner-only replay

Original owner SHA256 is `d367d02657c524349fd841940dd60a289174363d3a37946d4f0326902746072a`. Its Unix Meterpreter path calls `read` on the Process returned by `execute`. The actual loaded class exposes its channel, while the absent read alias yields nil. The owner reaches its existing empty-output failure and leaves a channel unread. This is not presented as a NoMethodError.

The final-contract original run `20261118T031555-e14637` has **2 examples/1 failure**, no pending/outside errors, three calls and two genuine root sessions. Shell collection and same-instance repeat store two correct files. Meterpreter reaches native process execution, prints `Could not retrieve environment variables`, stores no loot and leaves channel 1; the operator cleanup records closing that exact channel. Native current/initial environment proof, all selected recovery and Docker teardown pass.

The one-line repair uses `create_process('/bin/sh', args: ['-c', 'env'])`. The existing helper captures output and closes its channel/process. Other session/platform branches, metadata and stdout/raw-loot behavior stay unchanged. Final-contract replay `20261118T031855-e345b9` passes **2/0**, with all three raw files and no channel left for operator cleanup. **Exactly one of 53 inputs changes: the owner; all 52 spec/fixture/helper inputs remain identical.** Fixed owner SHA256 is `deb7503fbaee4f3df31e21651fcbd9cea757bdc404504405a2066e080ef2a626`. Original bytes were explicitly restored for the fresh baseline while the prepared fixed commit remained intact; actual source hashes, rather than Git HEAD alone, identify executed code.

Focused API contracts produce **13 examples/6 failures** on the original and **13/0 twice** on the repair; the parent independently passes **13/0**, including after import. Comparable cohorts have zero pending/outside/support examples or outside errors. Real Process construction, aliases, packet setup, capture/cleanup and Post::Common execute with disclosed client/channel transport, UI, session and persistence doubles. Synthetic chunk/initial-empty/128 KiB/repeat and alternate-session contracts are not native qualification. Initial loading/double/scope attempts are preserved and excluded. Syntax, scoped RuboCop, msftidy and whitespace checks pass.

## Preserved harness and observer failures

The first functional attempt `20261118T025853-273666` has **zero owner calls**. The selected ELF shell clears inherited environment, so the real session lacks the supplied PATH. Cleanup also calls a Meterpreter channel API on a shell, and the initial Meterpreter marker procedure fails native existence verification. That attempt and its selected recovery errors are sealed; Docker teardown still removes the stack. The corrected harness uses a genuine generated command payload for the shell, type-specific channel handling and the existing PostgreSQL profile's bounded native marker procedure. Shared qualified helpers remain unchanged.

A clean first owner cohort `20261118T030359-b3734f` reproduces the original 2/1 defect. Its intermediate fixed replay `20261118T030842-c5be51` stores all three files and closes the channel, but its PATH assertion incorrectly compares current output against initial proc data. That replay is preserved as an observer-contract failure. Adding independent live getenv proof is followed by the fresh original/fixed comparison above. No failing cohort is silently reclassified as passing.

## Final aggregate

Run `20261118T032354-af320d` passes **6/0**, zero pending/outside errors, in **155.6 RSpec seconds**, including prerequisites and recovery.

| Case | Actor | Calls | Raw loot |
| --- | --- | ---: | ---: |
| Shell standard values and same-instance repeat | root | 2 | 2 |
| Meterpreter standard values and same-instance repeat | root | 2 | 2 |
| Shell standard values | labuser | 1 | 1 |
| Meterpreter standard values | labuser | 1 | 1 |
| Shell large value | root | 1 | 1 |
| Meterpreter large value | root | 1 | 1 |

All eight native-derived value maps agree with stdout and actual PostgreSQL loot records/files, including empty strings, UTF8, embedded equals signs and multiline values. Large shell/Meterpreter loots contain **65,948** and **66,064** bytes, including the complete long value/end marker. Loot type is `unix.environment`, content type is `text/plain`, and each record has its actual session address. Credential-core counts remain zero. Both root repeats reuse the same module instance and create distinct loot records.

There are three genuine shells and three Meterpreter sessions: four root and two ordinary users. Eight native env-program controls, six actual session process/environment proofs and three live getenv observations supply independent prerequisites. All owner calls finish without new channels or live descendants. No operator channel close or process signal is needed in the final cohort. Actual session and launcher PIDs disappear; exact hash/UID-checked payload copies and markers are removed, database session rows close, and all six case selectors are removed. Framework ends with no sessions/jobs. Selected system/home/fixture/health-service state matches before/after; logs/counters and the entire filesystem are not claimed unchanged.

At most two capped containers run in one serial stack: target 512 MiB/0.5 CPU and reporting 384 MiB/0.25 CPU, equal memory/swap, PID128 and init. The Framework console runs on the host. Actual Docker limits and eight zero OOM/PID-limit snapshots pass; published ports bind only to loopback. The database volume and both networks are individually absent and Docker is empty. All **54** final inputs match. The read-only final trace seal has **99 entries**, manifest SHA256 `0ee02ccf80c6cc6cc4dae10d54149c7bf6a2e517a81e02258feea5c76911d32d`; original/native/replay and unit-source evidence is retained separately.

## Remaining scope

The existing `unloadable Meterpreter extension: stdapi_fs` compatibility warning occurs in both original and fixed runs. Required native sysinfo/process/getenv and all selected owning calls work after the repair, but the warning's underlying cause remains unverified and is deferred. This does not establish universal session-feature compatibility.

Windows registry and genuine Windows/PowerShell sessions, other OS/architectures/releases, additional payload delivery families and transport-loss behavior remain unqualified. A Linux PowerShell binary is not substituted for Framework's Windows PowerShell session. The continuation parser is specific to controlled fixtures without variable-looking continuation lines. No human Scenarios are invented or changed. The broader campaign remains active; no PR is created.


The prior [NickServ checkpoint SMB test](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44225940648/job/134539002968) and [report job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44225940648/job/134540745482) both prove `dwelch-r7/metasploit-framework@ac2ac8198ccd829c4f63c14848de7f56c9b7161e`, with **20/0**. These jobs predate the environment repair; its local six-case evidence is independent. CI source checks add no module qualification.
