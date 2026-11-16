# Photo Gallery credential gathering lab

These profiles install unmodified, checksum-pinned official Photo Gallery by
10Web 1.5.82 and 1.6.0 archives into WordPress 6.8.3 / PHP 8.3.28 with MariaDB.
The [original disclosure](https://wpscan.com/vulnerability/0b4d870f-eab8-4544-91f8-9c5f0538709c/)
identifies CVE-2022-0169 and its 1.6.0 fix. The official release diff changes
the tag-filter escaping in `framework/WDWLibrary.php`. The existing human
module guide still includes 1.6.0 in its affected range; that guide and its
Scenarios are preserved for human review.

Prepare the official archives, then run one profile from the Framework root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby test/module_targets/photo_gallery/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb photo_gallery
```

Additional profiles are `photo_gallery_prefix`, `photo_gallery_table_prefix`,
`photo_gallery_low_limit`, `photo_gallery_fixed`, `photo_gallery_absent` and
`photo_gallery_unrelated`. The low-limit profile sets MariaDB's real
`group_concat_max_len` to 96 bytes. Each stack has at most three containers:
app 0.5 CPU / 384 MiB, MariaDB 0.5 CPU / 512 MiB and PostgreSQL reporting
0.5 CPU / 256 MiB. Each has 128 PIDs, an init process and equal memory/swap
limits. Published ports bind ephemeral loopback ports. Framework runs locally
with the existing bundle; the guarded launcher serializes stacks and removes
the project's containers, networks and volumes on completion or failure.

WordPress activates the genuine plugin and lets it create its schema. The
lab creates a gallery and tagged image through `GalleriesModel_bwg`, saves
shortcodes through `ShortcodeController_bwg`, and publishes an ordinary page
through WordPress. The image and thumbnail are generated from PHP GD source.
The CLI installer normalizes ownership to the user that serves real HTTP
requests. Vendor source, SQL execution and HTTP responses remain unmodified.

Independent controls verify ordinary gallery rendering, exact PNG bytes,
matching and nonmatching tags, and shortcodes with visible and hidden titles.
Separate SQL queries distinguish complete values, SQL NULL and empty strings
in real title and image-alt output. The fixed release must keep normal gallery
operations healthy while returning none of the injected frames. The generic
error fragment on that release supports no product fingerprint or Safe result.

Functional cases compare real PostgreSQL credentials, printed complete hashes
and exact loot contents with native database values. They cover the default
`COUNT=5`, limited extraction, `COUNT=0` for all users, AutoCheck enabled and
disabled, nondefault `SHORTCODE_ID=42`, and hidden titles with shortcode 43.
Every selected public operation runs twice. Wrong paths, a real PostgreSQL
endpoint, the fixed release and absent/unrelated applications must refuse
collection without saving credentials or loot. Before/after snapshots check
users, gallery data, tags, pages, shortcodes, schema, source and image bytes.

Calibration findings and runtime status are maintained in the
[verification record](../VERIFICATION-20261116-photo-gallery.md). Other plugin,
core and PHP releases remain outside these profiles' scope.
