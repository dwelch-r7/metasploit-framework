# Metabase 0.42.1 configured target

Reuses the [native Metabase lab](../metabase/README.md). The profile asserts Appears detection and a missing-token rejection before POST.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb metabase_configured_042
```

See the central lab guide for provenance, controls, resource limits and qualification scope.
