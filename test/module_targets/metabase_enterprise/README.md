# Metabase 1.46.6 configured target

Reuses the [native Metabase lab](../metabase/README.md). The profile asserts Appears detection and command execution and Bash sessions.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb metabase_enterprise
```

See the central lab guide for provenance, controls, resource limits and qualification scope.
