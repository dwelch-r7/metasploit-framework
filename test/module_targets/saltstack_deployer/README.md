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
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb saltstack_deployer_3000_1
```

The diagnostic tests calibrate native x86/x64 ELF execution with ordinary public
handlers before invoking the unchanged local module from both declared session
types. Real session RPC, per-host proof files, process identity and reporting
database rows establish where callbacks landed. Harness fallback deletion is
recorded separately and does not satisfy module cleanup expectations.

Registration is not qualification. This profile is under investigation; no
successful module outcome is claimed here. The module's current check establishes
only the availability of a salt-master executable.

The serial launcher removes all five containers and the network on completion.
Three Salt daemons total 512 MiB/0.5 CPUs; Framework and PostgreSQL bring the
aggregate to 1,408 MiB/1.7 CPUs, the same limits as the collection lab. All
containers have bounded task counts, and runtime state lives in bounded tmpfs.
