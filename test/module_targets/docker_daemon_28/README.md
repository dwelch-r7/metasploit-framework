# Docker Engine 28 owner execution

Uses the shared Debian cron/registry/nginx target with official digest-pinned Docker Engine 28.0.4 binaries. The shared build argument selects the Engine image; the rest of the recipe and resource bounds are inherited. Native controls independently passed real create/start/wait/delete, target-root writes, normal cron, registry push/pull and authenticated/verified-TLS gateways before this owner profile was introduced.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb docker_daemon_28
```

The eleven-case suite checks direct/proxied detection and denied/refused probes, then opens, uses and closes two Linux x64 and two Python Meterpreter sessions. The runtime version must be exactly 28.0.4. The complete eleven-case owner suite passed with four used/closed root sessions, source cleanup before test cleanup, unchanged core processes and no OOM/PID-limit events. Native controls and owning execution remain separate evidence records.

See [the shared recipe and cleanup contract](../docker_daemon/README.md) and [the verification record](../VERIFICATION-20261115-docker-daemon.md).
