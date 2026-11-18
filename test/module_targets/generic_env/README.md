# Generic environment collection target

This opt-in profile uses genuine Linux processes, controlled environment values,
real shell/Meterpreter callbacks and actual PostgreSQL loot reporting. Six cases
cover root and ordinary-user sessions, empty/spaced/equals/UTF8/multiline values,
a bounded 64 KiB value with an end marker, and same-instance repeats for both
session types. Native prerequisites alone do not qualify the owner.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb generic_env
```

One serial stack runs two capped containers (target512MiB/0.5CPU and
reporting384MiB/0.25CPU), equal memory/swap, PID128/init, loopback publication
and a real host Framework console. Actual actor/PID/environment, source and
raw loot are checked. Selected state, channels, descendants, sessions, markers,
payloads and Docker resources must recover. Genuine Windows/PowerShell and
other platforms remain separate prerequisites.

The shell uses Framework's generated `cmd/unix/reverse_bash` command, preserving
its controlled environment; the target is Linux although shell metadata reports
Unix. The initial ELF shell choice clears inherited environment and is retained
as a setup failure. Meterpreter uses a genuine generated Linux/amd64 ELF.

Independent native `env -0` controls validate all fixture values under both OS
users. Actual session PID/UID and initial `/proc/PID/environ` are verified.
That file reflects the [initial execve environment](https://www.man7.org/linux/man-pages/man5/proc_pid_environ.5.html),
so Meterpreter's independent native getenv RPC supplies current PATH/LANG values
after startup changes. All controlled values must remain intact; owner stdout
and exact raw-loot values are compared against this native reference. The
continuation parser is specific to these fixtures and makes no general
environment-file parsing claim.

See the [verification report](../VERIFICATION-20261118-generic-env.md) for actual
results, preserved harness/observer failures and the existing `stdapi_fs`
compatibility warning. Other platforms/releases, Windows/PowerShell sessions,
additional payload families and transport loss remain unqualified.
