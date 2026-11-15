# Drupal 7 root PHP shell profile

Run from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb drupal7_php
```

This two-case profile preserves the original root PHP memory and dropper shell
cases. Each opens and uses a session twice and verifies delivery cleanup. It
starts only the genuine root Drupal 7.57 installation, MariaDB and Framework,
with fresh state, service resource caps and independent native controls.

The other five original PHP cases remain in `drupal7_php_staged` (one),
`drupal7_php_prefix` (two) and `drupal7_php_assert_off` (two). The 19 command and
Linux cases are divided among six separate profiles. See the [Drupal 7 guide](../drupal7/README.md)
for source provenance, the full partition and coverage limits. No execution
result is implied by registration, and existing human scenarios are preserved.
