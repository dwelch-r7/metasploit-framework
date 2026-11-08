# Redis module targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb redis
```

Three official Redis images, pinned by digest, provide Redis 6.2.14 with and
without authentication and Redis 7.2.4 with protected configuration defaults.
They have no host filesystem mounts. The runner publishes random loopback ports
and removes the containers and their anonymous data volumes afterward.

The suite independently verifies the version and authentication using
`redis-cli`, seeds strings/lists/sets/sorted sets/hashes and a second database,
and invokes real module entry points:

| Module | Cases |
|---|---|
| `auxiliary/scanner/redis/redis_server` | INFO and PING on all three services |
| `auxiliary/scanner/redis/redis_login` | Authenticated and unauthenticated services, wrong password |
| `auxiliary/gather/redis_extractor` | All seeded types and both databases, actual loot contents, empty keyspace |
| `auxiliary/scanner/redis/file_upload` | Repeated open/authenticated writes, failure recovery, original state preserved, protected-config check |

Lab password on `authenticated`: `module-test-password`. The file-upload target
is `/tmp/module-target-upload.rdb` inside the disposable container. Its contents
must include a known marker; a success message alone is insufficient.

Upload state uses separate native CONFIG GET requests with validated field names
and values. Redis 6.2 rejects multiple patterns while returning a zero CLI exit
status, so equality of unvalidated command output would not prove preservation.
The suite also independently establishes failed saves to `/proc` and a directory
destination, plus rejection of a missing directory. After each module failure,
configuration, exact key set and sentinel data must match their initial state,
and two fresh uploads must succeed.

The initial upstream baseline exposed no public file-upload check even though
the module defined one. The accompanying correction exposes the scanner check,
reports protected Redis 7 defaults as Safe, and uses Appears for readable settings
that have not demonstrated a write. See [the campaign record](../CAMPAIGN.md).
ACL users, TLS, replication exploits,
large/fragmented responses and extraction limits remain to be covered.
