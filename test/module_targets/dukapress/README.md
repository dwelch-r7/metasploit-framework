# DukaPress file disclosure

The profiles use genuine WordPress 5.2.4/PHP 7.3.11 with official checksum-pinned
DukaPress 2.5.3 and 2.5.4. The original plugin uses PHP's historical
`create_function` API, so a compatible runtime is selected through the shared
WordPress Dockerfile's `WORDPRESS_IMAGE` argument. Its modern default is retained.
The affected and fixed plugin sources, activation and actual native file behavior
are checked before any module action. No endpoint or vulnerability is simulated.

Prepare archives and run selected profiles serially from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/dukapress/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb dukapress dukapress_prefix dukapress_fixed dukapress_absent dukapress_unrelated
```

| Profile | Genuine target | Expected behavior |
| --- | --- | --- |
| `dukapress` | 2.5.3, root installation | Affected check; exact file loot; missing/empty/depth/path controls |
| `dukapress_prefix` | 2.5.3 under `/wordpress` | Same file contracts with traversal depth 8 |
| `dukapress_fixed` | 2.5.4 | Fixed check and no file loot |
| `dukapress_absent` | WordPress without the plugin | No affected check or file loot |
| `dukapress_unrelated` | Genuine Apache | No affected check or file loot |

Normal stacks have two capped containers: WordPress at 0.5 CPU/384 MiB/128 PIDs
and MariaDB at 0.5 CPU/512 MiB/128 PIDs. Apache alone uses 0.25 CPU/128 MiB/128
PIDs. All use init. Only a random loopback application HTTP port is published;
the database stays on an internal network. Framework runs in the existing host
bundle at reduced scheduling priority with isolated configuration/metadata.
Its processes and memory remain outside target cgroups. Each stack is removed
before the next starts. Archives stay outside Git in the ignored verified cache.

Native CLI checks run as the web user and record installed versions, source and
archive hashes, account state, file readability and actual file bytes. Anonymous
HTTP probes verify exact disclosure, fixed refusal, empty/missing files and an
insufficient depth. Owner loot must have the native file's exact length and
SHA-256; HTTP 200 or nonempty output alone cannot qualify it. Repeats cover system
file reads, UTF-8/NUL/non-UTF-8 content, a Unicode filename with whitespace,
relative paths, natively refused quoted paths and missing installations. Output is retained as bytes so
binary console text is not misinterpreted as UTF-8.

Depth 7 reaches `/` from the root plugin directory. The subdirectory adds one
level and uses 8 explicitly; this is deployment configuration, not a source fix.
WordPress adds escaping to request values; the original endpoint does not remove
it before opening a path. An existing filename containing an apostrophe is
natively refused in this configuration, so it is a negative control rather than
a promised disclosure. The installed core helper transformation is recorded.
The endpoint cannot distinguish an empty file from a failed read, so empty-file
controls expect no claimed download. They are not positive disclosure proofs.

Postflight checks known files, user/plugin state, empty console sessions/jobs and
zero target OOM/PID-limit counters; normal application/PHP session audit artifacts
are allowed until teardown. These profiles do not change account passwords.
Default CI excludes the functional examples. TLS, multisite, other plugin/core/
PHP releases and architectures remain separate coverage. Read actual result and
cleanup receipts before counting a profile. No human Scenarios are generated.
