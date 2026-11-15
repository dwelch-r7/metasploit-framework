# Docker daemon registry delivery

Pushes the pinned native root filesystem to the genuine local Distribution registry. An independent Docker API pull must restore the exact native image before testing the owner. The requested tag is then removed, so the owner must pull it itself. A second owner execution tests the cached image path. Both declared targets open, use and close real Meterpreter sessions. A nonexistent tag exercises the native registry error path.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb docker_daemon_registry
```

The registry is inside the disposable target. No external registry credentials, host port or host Docker socket is used. See [the daemon profile](../docker_daemon/README.md) for resource and privilege boundaries.

An exact-tag boundary case keeps `:3.20` cached while only `:3.2` exists in the registry. The owner must pull the requested tag; matching the longer cached tag as a substring is insufficient.

Recorded qualification: the fixed four-case replay passed with six real used/closed root sessions. Each of the three requested image references was pulled once and reused on the second execution, including `3.2` while only `3.20` was initially cached. The nonexistent tag was rejected. Source files and inner containers were removed before test cleanup; parent teardown confirmed no remaining containers. Native evidence is retained with the campaign verification records.
