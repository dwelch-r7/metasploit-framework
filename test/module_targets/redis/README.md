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
| `auxiliary/scanner/redis/file_upload` | Two consecutive real RDB writes, original data/configuration preserved, modern protected-config check |

Lab password on `authenticated`: `module-test-password`. The file-upload target
is `/tmp/module-target-upload.rdb` inside the disposable container. Its contents
must include a known marker; a success message alone is insufficient.

The initial upstream baseline exposed no public file-upload check even though
the module defined one. The accompanying correction exposes the scanner check,
reports protected Redis 7 defaults as Safe, and uses Appears for readable settings
that have not demonstrated a write. See [the campaign record](../CAMPAIGN.md).
ACL users, TLS, replication exploits,
large/fragmented responses and extraction limits remain to be covered.
