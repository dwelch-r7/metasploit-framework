# Photo Gallery SQL injection validation

Status: native calibration complete; functional qualification pending. This
record adds no runtime coverage counts. Seven genuine profiles and 33 cases are
drafted under [photo_gallery](photo_gallery/README.md).

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

The separate repair worktree is implementing framed extraction and an optional
shared strict SQL-result contract. Focused source validation, genuine profile
runs and a Depicter replay remain pending. No new coverage is qualified here,
and no PR is created.
