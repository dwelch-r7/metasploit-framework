# Salt minion deployment lab

The genuine pinned Salt 3000.1 master and two minions run in separate containers.
Their filesystems must remain separate: native Salt deployment copies identical
paths between hosts. A native control first proves authenticated encrypted RPC,
selection, exact copy/decode bytes, executable mode and independent host identity.

Build the source-pinned Salt image and its collection layer first, then run:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  docker compose -f test/module_targets/saltstack_zeromq/compose.yaml build target
DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  docker compose -f test/module_targets/saltstack_gather/compose.yaml build target
DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb saltstack_deployer_3000_1 \
    saltstack_deployer_x86_meterpreter saltstack_deployer_x64_shell \
    saltstack_deployer_x86_shell
```

Each profile calibrates its exact native ELF payload with an ordinary public
handler before invoking the local module from both declared master session types.
The master Meterpreter is native Linux x64, matching the module documentation;
its exact public handler ELF is started by administrative fixture setup. The
master shell is started through authenticated Salt RPC. Neither setup establishes
an unauthenticated exploit. Four profiles cover x86/x64 and shell/Meterpreter
output sessions. The second
owning deployment selects one minion and disables the calculation pause. Real
session RPC, per-host proof files, process identity and reporting database rows establish where callbacks landed. Harness fallback deletion is
recorded separately and does not satisfy module cleanup expectations.

Registration is not qualification. Consult the
[verification report](../VERIFICATION-20261112-saltstack-deployer.md) for actual
results, remaining failures and tested limits. The module's current check
establishes only the availability of a salt-master executable.

The serial launcher removes all five containers and the network on completion.
Three Salt daemons total 640 MiB/0.5 CPUs; Framework has 640 MiB and PostgreSQL
has 128 MiB. The aggregate is 1,408 MiB/1.7 CPUs, the same limits as the collection lab. All
containers have bounded task counts, and runtime state lives in bounded tmpfs.

Cgroup v2 OOM and PID-limit events must remain zero. Native copy/decode controls
run before the suite; final controls verify daemon/source identity and fresh
authenticated ping responses after the owning deployments.

Python HTTPS master execution and file cleanup were observed, but its remote
process termination remains unresolved and is not included in qualification.
See the investigation report for the retained failure evidence.
