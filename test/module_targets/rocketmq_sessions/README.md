# RocketMQ execution and session lab

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb rocketmq rocketmq_sessions rocketmq_fixed_guard rocketmq_commands
```

This profile reuses the [genuine RocketMQ targets and SDK controls](../rocketmq/README.md).
It runs two containers total, capped at 1,408 MiB/1.25 CPUs, with 256 PIDs per
container, no extra swap, no privileged mode and random loopback NameServer
bindings. Profiles run sequentially; Framework metadata may be reused normally
within the same invocation. No first-profile cache is supplied manually.

Before owning calls, ordinary handlers generate the direct Bash and default
staged fetched Linux Meterpreter commands. The handler's encoding requirement is
copied from the real exploit's bad-character metadata before normal generation.
The already generated command is read without regenerating it, streamed to a
temporary UID3000-owned script with a verified SHA256, and launched directly.
Each calibration must open and use a real session and finish remote PID/socket,
host session, listener and fetched-file cleanup before the exploit is tried.
No RocketMQ request handler or owning method is replaced.

Owning cases exercise both payload families twice, repeat with AutoCheck
disabled. The separate [fixed-release guard](../rocketmq_fixed_guard/README.md)
verifies automatic refusal twice. Successful
sessions must create a fresh file through the session API, have an actual
UID3000 process and connected socket, then exit remotely. The module must
discover Broker port10921; a call-through observer records the actual TCP peers.

Native SDK snapshots compare the full logical broker configuration and server
PID before and after each run. These strict restoration assertions are diagnostic:
a difference must be investigated against the real target and module contract.
On failure, a separately recorded native SDK recovery restores only the known
Home/filter-count values. Recovery cannot make the failed owning case pass.
The original state and actual difference remain in the run artifacts.

This profile does not become qualified merely by registration. Consult its
actual functional result, native calibration records and dated verification
report. The [command-only profile](../rocketmq_commands/README.md) covers asynchronous
generic commands separately. Forced execution on fixed targets, other releases,
authentication, IPv6 and binary serialization remain separate work.
