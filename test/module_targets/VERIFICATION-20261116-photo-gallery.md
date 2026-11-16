# Photo Gallery SQL injection validation

Status: qualified in seven current profiles. Photo Gallery adds one owner,
seven profiles and 33 cases, advancing historical campaign coverage to **262
runtime owners in covered paths, 421 profiles and 3,491 functional cases**.
The [lab](photo_gallery/README.md) retains reproducible genuine targets. A
separate seven-profile Depicter replay adds no counts.

## Native setup and release boundary

Official `photo-gallery.1.5.82.zip` and `photo-gallery.1.6.0.zip` archives are
pinned by size, SHA-256 and seven installed source hashes in the release catalog.
Both activate and serve ordinary galleries on WordPress 6.8.3 / PHP 8.3.28.
The real plugin creates its schema, gallery, tagged image and shortcodes. A
published WordPress page and exact GD-generated PNG bytes establish ordinary
operation before independent SQL controls.

The [original disclosure](https://wpscan.com/vulnerability/0b4d870f-eab8-4544-91f8-9c5f0538709c/)
identifies 1.6.0 as fixed. The official source diff changes the tag-filter
callback from `sanitize_text_field` to `esc_sql`. Native UNION probes extract
the database and complete user/hash values on 1.5.82; the same probes produce
no injected values on 1.6.0, whose normal galleries, tags and PNG requests
continue to work. This establishes only the two pinned releases. The existing
human guide's affected-range statement includes 1.6.0 and needs human review;
its whole file and Scenarios are preserved.

Two native fixture errors were corrected before module diagnosis: the CLI
installer initially left uploads unwritable by the HTTP user, and the direct
shortcode loader omitted the vendor AdminView base. Their raw attempts remain
sealed separately. No module call occurred in either failed setup.

## Confirmed original module failure

The exact original owner SHA-256 is
`fffcf44b03c302b189df01238736702b6538a9f0685521777605f0106bd6604e`.
Two real public `check` calls return Safe despite successful native injection.
The recorded module responses contain each actual canary after the normal
photo caption. Independent Nokogiri parsing preserves that ordering; the
original `at_css('div.bwg-title2')` selects the ordinary caption first.

The original observation has 95 sealed entries under
`/Users/dwelch/.codex/reports/photo-gallery-owner-1.5.82-20261116T083336-seal`;
manifest SHA-256 is
`a067dc4dc7256c13f4b5a4c2e6d18c402d566a83f2e371d1e256ad9a60175439`.
Its diagnostic tool completed successfully; the module did not meet its
expected contract. These are distinct results.

## Extended independent controls

Fourteen framed native scalar queries on each release cover database identity,
SQL NULL, empty strings, row count and all four complete user/hash byte pairs.
Shortcodes 1 and 42 render the frame in both title and image-alt channels;
shortcode 43 hides titles and retains it in the image alt. The query suppresses
ordinary rows with `AND 0`, and its string literals use hex notation. Identical
frames from the two channels are duplicate renderings of the same scalar.
All fourteen affected queries return their exact expected frames; all fourteen
fixed queries return none. Native source, schema, users, gallery data and image
snapshots are unchanged before and after.

The fixed negative body is a generic 98-byte `wd_error` fragment. It provides
no stable product fingerprint, so a missing frame alone cannot justify Safe.
All native attempts used at most two capped containers. Their project
containers, networks and volumes were removed, global container inventories
were empty and the advisory lock was released.

The extended native seals are:

| Release | Entries | Manifest SHA-256 |
| --- | --- | --- |
| 1.5.82 | 71 | `550bc74a97dbe007e5f226c4fd59150ec2a2c95a36d99f06d371e170b3d04012` |
| 1.6.0 | 71 | `624b45d38fb575b17d0d8a6f8e07d344264c335d386d65c19803bb9bd59895fe` |

## Source repair and focused contracts

Worker commits `639799a2801ef5374bc641885a22c4ec0844de4e` and
`a3111ac01ad32a99fbe9211d9afc25b1b365bc2b` were imported as `b6fd5c5c587`
and `73e82687c26`. Photo Gallery now suppresses ordinary image rows, frames
each scalar with query-specific hexadecimal literals, and reads exact matching
title and image-alt frames. Identical renderings are deduplicated; malformed,
missing or conflicting frames fail without reporting credentials. SQL NULL
and empty strings remain distinct. COUNT and SHORTCODE_ID are registered with
the original effective defaults of five and one, and each run prepares fresh
query state and probes even when AutoCheck is disabled.

The existing MySQLi Common implementation has an optional `strict_results`
setting, disabled by default. It validates counts where consumed, built-in HEX
byte pairs and complete decoded rows while preserving trailing empty fields.
Caller options are copied for strict wrapping so reuse cannot affect a later
call with strict mode disabled. Depicter reuses that guard instead of local
decoder, SQL-text count detection and row-validation wrappers. The shared
WordPress SQL helper and both whole human guides are unchanged.

| Matched focused suite | Cases | Original failures | Repaired failures |
| --- | --- | --- | --- |
| Strict MySQLi results | 37 | 22 | 0 |
| Existing MySQLi Common | 31 | 0 | 0 |
| Retained Depicter contracts | 49 | 0 | 0 |
| Photo Gallery contracts | 45 | 45 | 0 |

Every side has zero pending or outside-example errors. Existing Common and
Depicter suites retain their exact source; all 162 final examples pass. Strict
lint retains one unchanged `Style/OptionalBooleanParameter` finding in Common's
existing `read_from_file` method, with original/final exit one. Both modules
and new specs have zero offenses; module msftidy, syntax and diff checks pass.
Initial lean-loader, synthetic HTML encoding and test-construction errors are
retained separately. An intermediate options-copy regression is also preserved.

The immutable worker archive contains 802 independently rehashed entries under
`/Users/dwelch/.codex/reports/photo-gallery-sqli-contracts-20261116`;
manifest SHA-256 is
`65416b06dfe5ec937d5b53d815f2b5dbab0bce127d2c2183f02a307db6c84ce8`.
The parent confirmed the exact file set and separately reverified nine benign
captured native bodies against source receipts and checksums. Query evaluation,
HTTP, persistence and UI in focused tests use explicit doubles; malformed
results are synthetic. These tests establish no additional native versions.

## Genuine profile results

All seven profiles pass all 33 cases and 66 public calls. Independent controls
make 246 native HTTP requests. Thirty-six exact loot files and 64 distinct
workspace credential rows match complete native users and hashes. Default,
limited and all-row extraction work twice with AutoCheck enabled or disabled;
nondefault shortcodes and hidden titles also collect complete credentials.
The fixed release, absent plugin, unrelated service, wrong path and real
PostgreSQL endpoint save no credentials or loot.

All 96 union declared inputs match current bytes across the seven passing
profiles. Actual container inspection verifies at most three services, CPU
limits no greater than 0.5, equal memory/swap limits, PID limits of 128, init
processes and loopback-only published ports. No service restarts, OOM events
or PID-limit events occur. Each exact project is removed before the next;
independent container/network/volume queries and global inventories are empty
at every completed teardown. No sessions or jobs remain.

All seven Compose configurations and exact case collections pass preflight.
Its 149-entry seal is
`/Users/dwelch/.codex/reports/photo-gallery-preflight-20261116T091725-seal`;
manifest SHA-256 is
`82b4de9fa12f961ae2a2b380b87795d81fc8682243a6c39e62c191a22ba2c56c`.
The runtime fixture revision is `1394c0b8fe7`; source/fixture inputs are frozen.
All seven Depicter revalidation profiles pass 31 cases and 62 public calls,
with 32 exact loot files, 44 workspace credential rows and 91 native HTTP
requests. Their 102 union inputs match current bytes. The shared-library
change therefore retains its previously qualified behavior in the recorded
paths; this replay adds no owner, profile or case. Broader library users retain
the default behavior and were not all replayed.

The qualification increment is applied once: 261/414/3,458 becomes
262/421/3,491 owners/profiles/cases. All fourteen current stacks are capped and
removed, Docker is empty and the advisory lock is free. Earlier campaign scope
remains historical. The broader campaign and recorded investigations remain
open. No PR is created.


| Profile | Cases | Calls | Loot files | Workspace rows |
| --- | ---: | ---: | ---: | ---: |
| `photo_gallery` | 9 | 18 | 12 | 22 |
| `photo_gallery_prefix` | 5 | 10 | 8 | 14 |
| `photo_gallery_table_prefix` | 5 | 10 | 8 | 14 |
| `photo_gallery_low_limit` | 5 | 10 | 8 | 14 |
| `photo_gallery_fixed` | 3 | 6 | 0 | 0 |
| `photo_gallery_absent` | 3 | 6 | 0 | 0 |
| `photo_gallery_unrelated` | 3 | 6 | 0 | 0 |
