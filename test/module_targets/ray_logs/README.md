# Ray modern log API component

The pinned official Ray 2.56.0 image uses the real CLI, scheduler, dashboard and
log-agent gRPC service. Native controls use two containers, 5,184 MiB and 1.1 CPUs;
owner profiles add the canonical Framework console within a three-container
budget. No source handler, response or node is simulated.

```sh
DOCKER_CONTEXT=default nice -n 10 bundle exec ruby test/module_targets/ray_logs/native_gate.rb --native
```

The native gate reuses the existing bounded command runner, campaign lock,
resource capture and exact teardown. The older Ray native gate hardcodes static
serving/version paths; this component selects its own immutable modern sources
and log SDK controls without changing previously qualified components.

Installed source/build identity and a real scheduled task precede ordinary SDK
log enumeration and exact retrieval of an owned log file. Controlled outside
paths, quoted/UTF8 names, directories, wildcard matches and missing paths have
separate native HTTP and SDK observations. Owned fixture bytes are verified and
removed. Driver history and product logs can persist until container teardown.
Native success does not qualify the owning enumeration/loot module. The module
prints paths and stores enumeration loot; it does not retrieve file contents.
The fixed-version comparison and owning profiles require separate evidence.

The initial 1,536 MiB target cap caused a kernel OOM during startup of nine
modern dashboard subprocesses, before any native/owner control. The current
3,072 MiB target cap retains one CPU. This budget needs actual validation;
it does not assert that the application consumes the full allowance.
Exited targets use a bounded read-only Docker archive to preserve internal
logs; cgroup diagnostics unavailable after exit remain explicitly unavailable.

At 3,072 MiB, startup no longer reported OOM, but dashboard subprocesses
failed thread creation under the inherited 512 PID/thread ceiling. This modern
component uses a 1,024 ceiling at the same one-CPU quota. Capture peak usage
and limit events; the configured allowance does not prove that it is sufficient.

A read-only startup sampler measured 738 threads before the 3,072 MiB cgroup
recorded kernel OOM kills. The current bounded plan gives Ray 5,120 MiB and
1,536 PID/thread slots, leaving headroom for its raylet/agent/task processes
after all dashboard heads start. The native fixture still uses two containers
and 1.1 CPUs. Only measured successful controls can validate this plan.
