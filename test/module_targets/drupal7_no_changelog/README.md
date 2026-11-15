# Drupal 7 no changelog profile

Run this 2-case profile from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb drupal7_no_changelog
```

This profile starts only `no_changelog`, `db`, and `framework`. It preserves the original
acceptance cases and repeat-run cleanup assertions. See the [Drupal 7 guide](../drupal7/README.md)
for genuine source/runtime pins, independent native controls, the complete case
partition and coverage limits. No execution result is implied by registration.
