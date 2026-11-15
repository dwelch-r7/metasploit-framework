# Docker daemon authentication barriers

Runs the genuine owner twice for each HTTP/TLS authentication barrier: missing credentials with AutoCheck, missing credentials with ForceExploit, and rejected credentials with AutoCheck disabled. Every actual HTTP request must be denied by the native gateway. No container, host artifact, session or handler job may remain.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb docker_daemon_auth
```

Native controls first establish real daemon responses with valid credentials and HTTP 401 with missing/rejected credentials. See [the daemon profile](../docker_daemon/README.md) for shared setup and resource bounds.
