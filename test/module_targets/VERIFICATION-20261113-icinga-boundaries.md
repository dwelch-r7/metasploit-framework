# Icinga release-boundary verification — 2026-11-13

## Summary

**228 modules qualified in covered paths, 264 profiles and 2,491 functional
examples.** This checkpoint adds two release-boundary profiles and 24 examples,
replays all five Icinga profiles, and corrects an affected-version description.
The inventory remains 5,179 source files, 230 registered sources, 275 pending
documented container hints and zero stale reviews. The broader campaign remains
incomplete. No pull request is created.

The owning module remains
`auxiliary/scanner/http/icinga_static_library_file_directory_traversal`.
Its description and guide incorrectly included 2.8.0–2.8.5 for CVE-2022-24716.
The [vendor advisory](https://github.com/Icinga/icingaweb2/security/advisories/GHSA-5p3f-rh28-8frw)
starts this issue at 2.9.0, through 2.9.5, and identifies fixes in 2.9.6 and 2.10.
Native requests against complete 2.8.5 release sources returned HTTP 404;
2.9.0 returned exact outside-file bytes. The older source also lacks the
vulnerable library controller. These establish a metadata defect, not an
operational failure of the module.

The isolated repair commit `1ceff973f260aef6bee30872cc7e40be9e7c829a` was imported
as `a7b6c808aeff518f789a6abbf15499a0379dfbdb`. The parent independently verified
that all operational Ruby bytes outside Description and the original guide's
`## Scenarios` through EOF are unchanged. The corrected source SHA-256 is
`c00c0d3929166fae06e74688dd44e3fcbadf1bc86a811a2e0eb71c41ff6f26eb`.
The expanded [lab](icinga/README.md) is committed as `782d18ffb0d5f17f4dd970079bb362f70d38e01f`.

| Profile | Application source | Cases | Public calls | Exact loot files |
| --- | --- | ---: | ---: | ---: |
| `icinga_2_8_5` | Unaffected 2.8.5 release | 12 | 28 | 0 |
| `icinga_2_9_0` | First affected 2.9.0 release | 12 | 28 | 8 |
| `icinga_2_9_5` | Official affected 2.9.5 image | 12 | 28 | 8 |
| `icinga_2_9_6` | Official fixed 2.9.6 image | 12 | 28 | 0 |
| `icinga_subpath` | Official 2.9.5 at `/icingaweb2/` | 12 | 28 | 8 |

The complete frozen replay `20261113T193719-38f8da` passed **60 examples with zero
failures, pending examples or outside-example errors**. All 140 public calls
returned. Controller, manager and independent observer exited zero; their PIDs
are absent. Elapsed time was 450 seconds including startup and teardown. All
60 selected input hashes remain current after committing the lab. The run tested
the selected bytes on `a7b6c808aeff518f789a6abbf15499a0379dfbdb`.

## What looks good

The two oldest profiles install complete SHA-256-pinned upstream release archives
on the same digest-pinned PHP 7.4.25/Apache image used for 2.9.5. They are source
installations, not claimed historical vendor binary images. All 2,466 original
regular files for 2.8.5 and 2,568 for 2.9.0 match independently derived release
manifests, before and after execution; only Apache URL configuration is excluded
and separately checked. Archive URLs, commits, hashes, file counts and manifest
hashes are recorded in [vendor.json](icinga/vendor.json). The source recipe
normalizes archived Apache configuration to the vendor image's root mapping;
the subpath variant changes that mapping to `/icingaweb2/`. Application PHP is
unpatched. The original 2.9.5/2.9.6 profiles still use their pinned official images.

Independent Python HTTP requests use exactly the owning module's target address
and ports. The parent audit correlates raw native HTTP and PostgreSQL command
outputs with the protocol and every loot snapshot, actual target-container IP,
source checksums and full source-manifest verification. The first console is
independently verified cold with both fresh metadata files; all later profiles
reuse only that invocation's verified metadata. No module method or response is
replaced.

Repeated public checks honestly detect the application without claiming its
version or proving exploitation. Repeated public runs verify exact multiline
text, leading/trailing whitespace, all 256 binary octets and raw UTF-8 filenames
on affected targets. The 24 persisted loot files match actual fixture bytes,
target host and metadata; existing row IDs and bytes stay stable. Old/fixed
releases, missing/unreadable files, directories, empty files, the unrelated PHP
server and the refused target port produce no false loot. Native HTTP 400/404
filename refusals are retained; unsupported encoded names are not counted as
successful file reads. All workspaces are isolated and all examples verify empty
Framework jobs and sessions.

Init, Apache and PHP server PID/birth identities, source, Apache configuration
and proof checksums match before and after. Only three capped containers run at
a time: target 256 MiB/0.5 CPU/96 tasks, Framework 768 MiB/1.5 CPUs/256 tasks,
and PostgreSQL 128 MiB/0.2 CPU/64 tasks. Combined RAM is 1,152 MiB, with swap equal
to RAM and loopback-only publication. Every recorded memory/PID event value is
zero across all fifteen service lifetimes.

All **36 final independent cleanup queries** pass: exact absence of fifteen
containers and five networks, each project's labels and the global container
inventory. Both one-container native profiles also passed their twelve separate
cleanup queries. The bounded guard exited zero, its PID is absent and both
advisory locks are free. No image or volume prune was performed.

## Concerns

No operational module defect was found in these covered paths. The original
false version-range text is corrected. Strict source lint and module tidy retain
one identical pre-existing duplicate RPORT warning, with zero new findings;
syntax and guide tidy pass. Both changed acceptance Ruby files pass strict lint.
All five rendered plans and actual target builds pass. The repair changes no
operational code, default, option, dependency or Framework library; no full RSpec
run or new metadata-only unit suite is involved.

The existing module labels saved loot as `text/plain`, including binary files;
these tests verify the exact bytes and recorded metadata, not MIME classification.

Other releases, PHP runtimes and deployment configurations remain untested.
The unaffected claim here concerns CVE-2022-24716 specifically, not the overall
security of an old Icinga release. Previously deferred `druid_js`,
`freeswitch_batch`, `superset_rce_owner` and `wordpress_admin` profiles remain
unqualified. Other remaining module candidates and the broader goal remain open.

## Suggestions

Continue the remaining valuable container-feasible modules, keeping genuine
native controls before source-failure classification, capped serial runtimes
and explicit cleanup. This checkpoint closes the earlier Icinga 2.8.x range
investigation without inventing a runtime failure or altering operational code.

Immutable local evidence under `~/.codex/reports/`:

- `icinga-older-native-controls-20261113`: 40 individually rehashed files,
  including complete release archives, source comparisons and cleanup receipts.
- `icinga-affected-version-fix-20261113-1ceff973f26`: 62 manifest entries and nine
  inputs, independently rehashed and matched to the primary checkout. Manifest
  SHA-256 `6e638eb67df0890205454af4858bb174998a49e755c15791226fdb709d214f7e`.
- `icinga-version-boundaries-qualified-20261113`: **448 individually
  rehashed files and 60 selected inputs**, including the complete frozen
  five-profile run. Manifest SHA-256
  `d866d011a208a351c027b1cdbc2495702a305150d354d608ea36b498db6ef855`.

AI tooling prepared the recipes/tests and report; an isolated source-fix worker
corrected the descriptions. Original human Scenarios remain byte-exact.
