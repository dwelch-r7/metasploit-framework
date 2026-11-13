# FreeSWITCH multi-host authentication lab

Run the independent-service profiles serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/freeswitch_batch/run.rb
```

Qualification is recorded in dated verification reports. Two real, pinned
FreeSWITCH 1.10.10 services use the existing event-socket configuration helper.
Profiles select identical passwords, different ASCII/Unicode passwords or one
loopback-only ACL. Both services pass independent framed-protocol and local CLI
controls before and after module calls. The reporting database also supplies an
independently verified closed TCP 8021 endpoint, while its PostgreSQL health
check remains successful.

Four containers run one profile at a time: two services, Framework and reporting
PostgreSQL. Total caps are 2,432 MiB, 3.3 CPUs and 832 tasks. Only application
ports are published on loopback. Logs, media directories and database state are
bounded tmpfs mounts; no persistent Docker volume is created.

Cases cover two-host lists in both orders, host files, concurrent scanner workers,
explicit and candidate-file passwords, AutoCheck on/off, forced scans, mixed ACL
and refused-port states. Each public case runs twice. Native controls establish
the correct result for each service. Passive capture and PostgreSQL rows verify
per-address attempts, credential identity, absence of blocked-host successes and
repeat behavior. Configuration, process and resource checks run after testing.
The capture-only runtime adds the real reporting-container IP as a peer filter;
module endpoints and the original runtime remain unchanged.
