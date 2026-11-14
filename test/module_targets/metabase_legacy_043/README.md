# Metabase 0.43.7.1 configured target

Reuses the [native Metabase lab](../metabase/README.md). The profile asserts Appears detection and command execution and Bash sessions.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb metabase_legacy_043
```

See the central lab guide for provenance, controls, resource limits and qualification scope.
