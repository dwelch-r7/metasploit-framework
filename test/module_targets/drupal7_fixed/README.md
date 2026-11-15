# Drupal 7 fixed profile

Run this 3-case profile from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb drupal7_fixed
```

This profile starts only `fixed`, `db`, and `framework`. It preserves the original
acceptance cases and repeat-run cleanup assertions. See the [Drupal 7 guide](../drupal7/README.md)
for genuine source/runtime pins, independent native controls, the complete case
partition and coverage limits. No execution result is implied by registration.
