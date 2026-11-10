# gogs_hooks target profile

This profile selects 10 functional examples. Retained campaign reports record
the exact qualified inputs and outcomes; selection alone is not qualification.

See the [shared Gogs guide](../gogs/README.md) for primary provenance, native
prerequisites, actual payload proof, limits and cleanup boundaries. This profile
runs at most 4 containers, including Framework and reporting DB when used.
Run only this family after an explicit serial resource grant:

```bash
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gogs_hooks
```

Wait for complete owned teardown before another family or any build starts.
The expected case count is a collection contract, not a qualification result.
