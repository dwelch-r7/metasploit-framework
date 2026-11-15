# Docker daemon shell delivery

Runs the genuine Docker daemon owner against Linux x64 and Python command shell payloads, twice each. The shared target, native controls, resource bounds and cleanup checks are described in [the daemon profile](../docker_daemon/README.md).

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb docker_daemon_shells
```

The Python shell payload launches a subprocess for each command. The test observes the persistent Python parent process and requests its remote termination; exiting a transient child would not prove that the payload stopped.
