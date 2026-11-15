# Docker daemon container naming

Exercises an explicit reusable name, preservation of an independently created stopped container with the same name, and an explicitly blank optional name. Session cases repeat, and cleanup is checked independently before the harness removes anything.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb docker_daemon_names
```

The collision control is removed only by its recorded native container ID after its full inspection document is compared. See [the daemon profile](../docker_daemon/README.md) for shared setup and resource bounds. The fixed three-case replay passed: four real root sessions were used and closed; the preexisting collision container remained byte-for-byte unchanged in its inspection record. Both explicitly blank-name executions followed the actual returned IDs, and source artifacts were absent before test cleanup.
