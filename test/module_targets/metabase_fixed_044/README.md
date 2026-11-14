# Metabase 0.44.7.1 configured target

Reuses the [native Metabase lab](../metabase/README.md). The profile asserts Safe detection and native rejection of forced execution.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb metabase_fixed_044
```

See the central lab guide for provenance, controls, resource limits and qualification scope.
