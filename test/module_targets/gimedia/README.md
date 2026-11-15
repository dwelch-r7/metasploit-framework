# GI-Media Library file disclosure

This target exercises `auxiliary/scanner/http/wp_gimedia_library_file_read`
against genuine GI-Media Library 2.2.2 and 3.0. It reuses the WordPress bootstrap,
database, archive preparation and pinned legacy runtime; application and plugin
source remain unchanged. The old plugin is tested on WordPress 5.2.4 / PHP 7.3.11,
using the image digest in [services.yaml](services.yaml).

The original module's public scanner `check` is unsupported despite its existing
version helper. The original recording separately confirms working file reads.
The focused repair exposes that helper through `check_host` and preserves the
download method. See the [qualification report](../VERIFICATION-20261115-gimedia.md)
for measured results, the original failure and remaining limits.

Prepare the checksum-verified [official plugin archives](releases.json), then run
the profiles individually from the repository root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby test/module_targets/gimedia/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gimedia
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gimedia_prefix
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gimedia_fixed
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gimedia_absent
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gimedia_unrelated
```

| Profile | Genuine target | Expected module behavior |
| --- | --- | --- |
| `gimedia` | 2.2.2 at `/` | Appears; exact file downloads |
| `gimedia_prefix` | 2.2.2 at `/wordpress` | Appears; exact file downloads |
| `gimedia_fixed` | 3.0 | Safe; removed download endpoint returns 404; no loot |
| `gimedia_absent` | WordPress without the plugin | Unknown; no loot |
| `gimedia_unrelated` | Independent static Apache page | Unknown; no loot |

The native preflight runs before any owner command. It checks installed/core/PHP
versions, archive and endpoint hashes, active plugin identity, service-user file
access and raw unauthenticated HTTP responses against actual file bytes. The
3.0 archive removes `download.php`; a real missing endpoint establishes this
negative control. The unrelated target has its own independently checked marker.

Affected profiles cover repeated system and binary reads, Unicode and quoted
filenames, relative paths, the default WordPress configuration/depth, missing
and empty files, insufficient depth and a missing installation. Every expected
download must create exactly one fresh loot file with the actual target length
and SHA-256. Repeated public checks and negative runs must create no loot.
The read-only identity comparison covers the fixture files, active plugin and
administrator password/activation-key fingerprints; it does not claim a full
database audit. Sessions and jobs must remain empty.

Each WordPress profile runs two containers: app 0.5 CPU / 384 MiB / 128 PIDs and
database 0.5 CPU / 512 MiB / 128 PIDs. The unrelated target uses one Apache container
at 0.25 CPU / 128 MiB / 128 PIDs. All use `init`; OOM/PID counters are checked before
and after. The database is internal-only, and HTTP uses a random loopback port.
The real Framework console runs on the host with isolated configuration and
metadata caches; its processes and memory are outside the container limits.

The guarded runner refuses startup when another container or guarded run exists,
and removes its stack and volumes even after test failure. The campaign also
checks the exact former container/network/volume identities and lock release
independently before starting the next profile. It preserves unrelated images
and volumes. Tests and raw console/native evidence live under the ignored
`tmp/module-target-tests/` directory.
