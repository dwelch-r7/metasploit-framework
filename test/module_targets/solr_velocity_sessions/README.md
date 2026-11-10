# Solr Velocity session profile

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb solr_velocity_sessions
```

This six-case profile reuses the genuine Solr targets and independent native
controls with fresh console, database and application state. It requires two
usable sessions per case across Java, Unix Bash and Linux x64 curl delivery,
with anonymous and authenticated access. See the
[Solr target guide](../solr_velocity/README.md) for setup, state restoration,
native provenance, controls and limits.
