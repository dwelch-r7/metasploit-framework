# Icinga file collection verification — 2026-11-13

## Summary

**Qualified in covered paths: 228 modules, 262 profiles and 2,467 functional
examples.** This checkpoint adds one owning module, three serial profiles and
36 passing examples. The inventory contains 5,179 source files, 230 registered
sources, 275 pending documented container hints and zero stale reviews.
The broader campaign remains incomplete. No pull request is created.

The owning module is
`auxiliary/scanner/http/icinga_static_library_file_directory_traversal`.
Its implementation is unchanged; SHA-256
`b4d276e4bc2ce3c188ff51b845e2880774bd47f8e9860c7d1b4ded46ea7ceeec`.
The [lab recipes and commands](icinga/README.md) and the matching functional spec
are committed in `e8c36be0dd3edf6564f30b39f8471a438104a57f`. The frozen run tested the same selected file bytes
on base `a142e6c8c804d8c866e82dbab079d36f7a3828cc`; all 56 selected inputs remain
current after committing. The module guide links the lab, and its original
`## Scenarios` through EOF remains byte-for-byte unchanged.

| Profile | Genuine application | URL prefix | Cases | Public calls | Exact loot files |
| --- | --- | --- | ---: | ---: | ---: |
| `icinga_2_9_5` | Official Icinga Web 2 2.9.5 | `/` | 12 | 28 | 8 |
| `icinga_2_9_6` | Official Icinga Web 2 2.9.6 | `/` | 12 | 28 | 0 |
| `icinga_subpath` | Official Icinga Web 2 2.9.5 | `/icingaweb2/` | 12 | 28 | 8 |

Run `20261113T191358-a65a69` passed all 36 examples, with no failures, pending
examples or outside-example errors. Its controller, manager and independent
observer all exited zero and their PIDs are absent. Total elapsed time was
291 seconds including startup and teardown. The first console was independently
verified cold, including both fresh metadata files; later profiles reused only
that invocation's verified metadata.

## What looks good

The official images are pinned by digest in [vendor.json](icinga/vendor.json).
The affected CLI identifies commit `053971c99dc1a4510beb64a888ea695cc14032dc`;
the fixed CLI identifies `e702d933e15b0907628091a03741baff1b6074df`.
Each image's StaticController checksum matches its exact release source.
The [vendor advisory](https://github.com/Icinga/icingaweb2/security/advisories/GHSA-5p3f-rh28-8frw)
identifies the unauthenticated disclosure and the 2.9.6 fix; the
[vendor patch](https://github.com/Icinga/icingaweb2/commit/9931ed799650f5b8d5e1dc58ea3415a4cdc5773d)
adds the missing asset-root/path validation. The lab changes Apache's URL mapping
for the subpath profile and adds public proof files and a genuine PHP static
server; it does not replace the application's disclosure implementation.

Independent Python HTTP controls use the exact target address and ports used by
the owning module. They run before and after each profile. The parent audit
correlates their raw command output, target-container IP, release checksum and
native state with the recorded protocol results. PostgreSQL command output is
also independently correlated with every saved loot snapshot.

All 84 public calls returned. Repeated `check` calls detect Icinga without a
version-based vulnerability claim, including the fixed release. Repeated `run`
calls verify exact multiline text, leading/trailing whitespace, all 256 binary
octets and a raw UTF-8 filename. The 16 persisted loot files match actual fixture
bytes and have the correct host, type, name and content type. Earlier records
retain their IDs and bytes; all twelve per-profile workspaces remain isolated.

Empty files, missing files, existing unreadable files, directories, the unrelated
PHP server and the refused target port produce no false loot. Native raw space
requests receive HTTP 400; encoded space and UTF-8 names receive HTTP 404. These
are genuine target refusals, not claimed successful filename support. Raw UTF-8
requests retrieve the real file on the affected targets. Init, Apache and PHP
server PID/birth identities, application source, Apache configuration and proof
checksums match before and after. Every example verifies empty Framework jobs
and sessions.

Only three containers run at a time: target 256 MiB/0.5 CPU/96 tasks, Framework
768 MiB/1.5 CPUs/256 tasks and PostgreSQL 128 MiB/0.2 CPU/64 tasks. Combined RAM
is 1,152 MiB and swap equals RAM. Target publications bind only to loopback.
All nine services' complete memory-event and PID-event counter records are zero.
The final independent cleanup audit passes all 22 queries: exact absence of nine
containers and three networks, each project's labels and the global container
inventory. The native-only phase used one container at a time and passed twelve
separate cleanup queries. The bounded tool guard exited zero, its PID is absent
and both advisory locks are free. No image or volume prune was performed.

## Concerns

No owning module defect was found in these covered paths. Earlier failures were
preserved before edits: a native-probe syntax error, an output-serialization
error, an Apache launcher error and Ruby keyword arguments in the fixture.
The complete 33-failure keyword run had passing native controls and no source
verdict; the corrected suite passed. A subsequent 36/0 run was also preserved
before correcting the closed-port oracle to use the owning network. The final
36/0 replay includes that correction.

The whitespace proof intentionally contains trailing spaces and a final blank
line; those are the only `git diff --check` notices. The remaining staged files
pass the whitespace check. Strict Ruby lint passes both changed Ruby files;
Ruby/Python/shell syntax, rendered Compose plans, actual builds and module-doc
lint pass. No Framework library/dependency changes or full RSpec run are involved.

The 2.8.x range historically mentioned by the module and other Icinga deployments
remain untested. This checkpoint establishes the exact two releases and URL
mappings above, including the official image's unconfigured setup state.
Previously deferred `druid_js`, `freeswitch_batch`, `superset_rce_owner` and
`wordpress_admin` profiles remain unqualified. This checkpoint does not close
those investigations or the broader module queue.

## Suggestions

Investigate the existing 2.8.x affected-version claim separately, then continue
the remaining valuable container-feasible modules with the same native-first
classification and bounded serial resource policy.

Local immutable evidence is retained outside Git under `~/.codex/reports/`:
`icinga-native-probe-syntax-20261113`,
`icinga-native-probe-output-20261113`,
`icinga-native-controls-20261113`,
`icinga-apache-launcher-setup-20261113`,
`icinga-ruby-keyword-fixture-20261113`,
`icinga-native-network-review-20261113`, and
`icinga-file-collection-qualified-20261113`.
The final receipt contains **354 individually rehashed files and
56 selected inputs**; manifest SHA-256
`7d6420a33d8bfddee799dc79a359e74b0b0d1bea53ce00ad5257825350da2d4a`.
The final source, native HTTP/SQL records, loot bytes, caps, cleanup records and
input digests were independently checked before publication. AI tooling prepared
the recipes, tests and this report; no human-only Scenarios were generated.
