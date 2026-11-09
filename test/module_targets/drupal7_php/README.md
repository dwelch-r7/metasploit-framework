# Drupal 7 PHP session profile

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb drupal7_php
```

This seven-case profile complements the 19-case `drupal7` profile. It uses the
same genuine source/runtime pins and installer through Compose inheritance,
fresh databases and independent native controls. Every PHP memory/dropper,
explicit/automatic and assertion-disabled fallback session case repeats twice,
including staged PHP Meterpreter. Actual commands and per-run file cleanup
are required. It uses the shared spec with a manifest-selected PHP profile.

See the [Drupal 7 guide](../drupal7/README.md) for source provenance, target
setup, the complete 26-case split and coverage limits. Existing human module
scenarios are preserved. A passing native profile does not qualify these
separate PHP session cases.
