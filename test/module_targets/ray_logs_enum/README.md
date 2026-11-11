# Ray log path enumeration owner

This profile uses the [modern native log component](../ray_logs/README.md),
unrelated Apache and the canonical Framework console. Three containers cap
the serial pipeline at 5,952 MiB and 2.1 CPUs; Ray's PID/thread ceiling is 1,536.
The full normal dashboard remains enabled. Allowances are limits, not reserved
or claimed actual usage.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_logs_enum
```

Before/after native controls bind installed sources and a real task to native
SDK/HTTP log enumeration and exact retrieval of an owned log. Owner fixtures
remain unchanged across repeated module calls, then are verified and removed.
Actual console paths and newly written exact loot are required for discovery,
explicit node IDs, ordinary log names, outside directories, UTF8/quoted/percent
names, glob/literal wildcards and empty files. Missing paths, unknown nodes and
unrelated-service check/AutoCheck paths have separate failure assertions.
This tests path enumeration and loot, not reading arbitrary file contents.
Only a single genuine node is covered; multi-node behavior remains separate.
The [fixed-release profile](../ray_logs_fixed/README.md) reuses these controls
with native gRPC/HTTP denials. A configured profile is not passing evidence.
