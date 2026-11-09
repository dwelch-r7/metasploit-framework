# Legacy MongoDB target

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mongodb_legacy
```

This digest-pinned original MongoDB 2.6.12 image predates initialization hooks.
A temporary localhost-only native daemon creates public rootuser/rootpass and
database-scoped testuser/testpass accounts plus small deterministic data, then
shuts down before the final open/authenticated daemon starts. Provisioning uses
native commands; it does not replace the database protocol with a stub.

Native clients verify real MONGODB-CR records, scoped permissions, enforcement
and 111 application records. The shared suite exercises version detection,
authentication fallback, exact hash extraction, cursor continuation and rejected
credentials/permissions. Modern schema enumeration is outside this profile.
No pass is implied by the target definition; see the [campaign](../CAMPAIGN.md).

Only random loopback ports are published. Data is ephemeral, with small files,
preallocation/journaling disabled for this disposable compatibility target.
See the [shared guide](../README.md) for evidence and cleanup.
