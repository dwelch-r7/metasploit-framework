# Memcached extractor targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb memcached
```

Official Memcached 1.4.39 and 1.6.26 images, pinned by digest, exercise the
extractor's `stats cachedump` and `lru_crawler metadump` paths. Independent,
bounded text-protocol requests verify each real server's version, stored value
and key enumeration before Framework runs. An empty-cache case checks that the
module does not invent extracted data.

The module is `auxiliary/gather/memcached_extractor`. Only loopback TCP access is
published; UDP amplification is outside this fixture. The module suppresses loot
and service reporting for loopback addresses, so these cases validate actual
console extraction, not loot persistence. Authentication, fragmented responses,
large values and preview/key limits remain to be covered.
