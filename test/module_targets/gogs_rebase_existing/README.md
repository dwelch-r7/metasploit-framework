# Gogs existing-repository profile

This bounded profile selects the five existing-repository examples from the
original ten-case rebase corpus. The paired own-repository profile selects the
other five; every original example body, repeat and assertion is retained.
The complete native gate runs before either profile's module calls.

Services extend the [same pinned configuration](../gogs_rebase/compose.yaml),
with at most five containers, 1,728 MiB and 2.45 CPUs. The common native profile
still describes the full ten-case logical corpus; each manifest selects five.
See the [shared guide](../gogs/README.md) for provenance, prerequisites, actual
payload/session proof, limits and operator cleanup boundaries.

After an explicit serial grant:

```bash
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gogs_rebase_existing
```

Selection is not qualification. Preserve natural failures and wait for complete
owned teardown before any other campaign project or build starts.
