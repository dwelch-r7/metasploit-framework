# Docker daemon gateway delivery

Runs six genuine owner sessions through an unprotected nginx gateway, HTTP Basic authentication, and TLS with HTTP Basic authentication. The native controls verify the actual TLS certificate and compare each gateway response with the real daemon response. The shared target, resource bounds and cleanup checks are described in [the daemon profile](../docker_daemon/README.md).

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb docker_daemon_gateways
```

Framework uses its normal HTTP client TLS policy. Certificate verification is proved independently by native controls; this profile does not claim that Framework verifies the self-signed lab certificate.
