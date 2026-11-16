# Drupal PostgreSQL EntityQuery qualification, 2026-11-16

One new runtime owner, eight profiles and 24 functional cases bring historical
campaign coverage to **264 runtime owners in covered paths, 436 profiles and
3,549 functional cases**. This is a current eight-profile increment; earlier
campaign coverage is historical and was not replayed. No PR is created.

The static queue contains 5,179 source files and 4,622 module candidates: 265
registered, 4,334 pending review, including 240 documented container hints.
Twenty-six reviews have no stale source hashes. The historical one-owner gap
between registration and runtime qualification is retained. A container hint
or registration is not a passing functional result.

All **94 public calls** pass: 46 `run` and 48 `check`. Captured results comprise
22 Vulnerable, 32 Safe and 40 Unknown outcomes for the configured resource and
field. Six workspace vulnerability rows and fourteen service rows remain
correctly deduplicated across repeated calls. There is no loot; Framework jobs
and sessions are empty after the cases. Native controls issue 78 independent
HTTP requests, and all 34 before/after container counter rows show zero OOM,
OOM-kill or PID-limit events. Every project, attached volume and attached
network is removed before the next profile. Each stack uses at most three
capped containers, with loopback-only published ports.

## Target and source provenance

The affected/fixed Core pair is 11.2.0/11.2.12, extracted as complete official
archives including their own bundled vendor dependencies. Both run on pinned
official Drupal PHP 8.4.8/Apache; the old Core/vendor tree is not overlaid.
PostgreSQL is actually 16.15; the unaffected comparison is MariaDB 11.2.2.
The application uses an ordinary database role. A separate ordinary PostgreSQL
role/database holds real Framework reports; the MariaDB profile has three
containers and the others two. Setup uses Core's installer, module installer
and entity APIs, without installing Composer or Drush into the project.

The [Core advisory](https://www.drupal.org/sa-core-2026-004) covers other release
branches; they are not runtime-qualified here. Only the configured article
resource, tested fields, HTTP transport and these deployment states are
qualified. Safe results for a case-sensitive field do not attest to other
fields in the same affected installation.

| Official archive | SHA256 |
| --- | --- |
| 11.2.0 | `68844e781b1f34e4689639088cdf531d091c4369cbd7ab909ebc619de6ad07f0` |
| 11.2.12 | `26811078ccf204dcb6091414e69a318c301cf14bf2ab886a02c3547ca23ddd2b` |

The whole human-written module guide and Scenarios stay byte-identical:
`7a5f38bb7e682cda49f45c88a0f8872ae38466005ed2ef394a0624195229005b`.
Relevant Core files, users, published nodes and field settings agree before and
after each profile; normal application cache/log activity is outside that
selected state fingerprint. Native API requests validate the actual article
UUID, Unicode title, matching/nonmatching filters and case sensitivity.
Distinct true/false requests establish the timing boundary. Identical anonymous
URLs can hit Drupal's page cache; the independent controls use distinct values,
and the module's own random filter markers stay enabled.

## Source correction and failure attribution

The source fix registers the already-consumed `TARGETURI` option. Before the
one-line change every one of eleven root cases caught the console's unknown
option warning. Native detection itself already worked; this does not imply
that every original operation was broken. After the correction the same root
case list passes, including the subdirectory configuration and real reports.
The scanner inherits public `check` through `MultipleTargetHosts#check`.

Original owner SHA256:
`9214a5c06a069e2654e5da1cf26364e8d04445aa1b631a7812e3c0ee4ac7811a`.
Qualified owner SHA256:
`b72a079d2f9c32bdaee9cf1d8c1dca2e38ca860748f6fa7ddcadcfee98f02647`.
The committed source/fixtures are `a7dbc0f85cc16cf9eba5bb177de88ca1b668064b`; their blobs match the
recorded tested inputs. Runtime records retain their actual earlier Git HEAD
and the exact working-file digests; this is not a claim that they checked out a
commit that was created afterward.

Earlier fixture/control faults remain preserved separately: guessed source and
archive paths, a Core-owned constant contaminating inspector JSON, anonymous
URL caching, an incorrect assumption that console check was unavailable,
MariaDB ANSI identifier quoting, and JSON:API returning 200 with access-omission
metadata rather than 403. The latter two stopped before any module call.
Four automatically started GitHub/AWS connector containers were explicitly
removed under the user's cleanup instruction; the final matrix sees no foreign
containers. Its global guard is personal orchestration; the committed launcher
continues to refuse unrelated containers rather than deleting them.

New Ruby/spec files have zero lint findings. Original and final module strict
RuboCop both exit 1 with the same two peer-prefix warnings; strict msftidy exits
2 because of those warnings. Captured HttpClient/Scanner messages have a single
manual peer prefix. No new offense is introduced and no blanket lint pass is
claimed. Syntax, Compose resolution, source checksums and diff checks pass.

## Runtime results

| Profile | Actual run | Cases | Public calls | Native HTTP | Containers |
| --- | --- | ---: | ---: | ---: | ---: |
| `drupal_pgsql_private` | `20261116T115031-ab2ee6` | 1 | 4 | 4 | 2 |
| `drupal_pgsql_empty` | `20261116T115200-a5fa57` | 1 | 4 | 4 | 2 |
| `drupal_pgsql_disabled` | `20261116T115329-c6de72` | 1 | 4 | 4 | 2 |
| `drupal_pgsql_unrelated` | `20261116T115458-fd46fc` | 1 | 4 | 2 | 2 |
| `drupal_pgsql_mariadb` | `20261116T115610-a04be7` | 3 | 12 | 16 | 3 |
| `drupal_pgsql_fixed` | `20261116T115804-617c8c` | 3 | 12 | 16 | 2 |
| `drupal_pgsql_prefix` | `20261116T115955-526f99` | 3 | 12 | 16 | 2 |
| `drupal_pgsql` | `20261116T120147-5dee63` | 11 | 42 | 16 | 2 |

Each normal case runs `run`, then `check`, twice in one isolated workspace.
A separate case performs two fresh checks without a prior run. Positive,
fixed-release, case-sensitive, custom-field, invalid-field/resource/path/host,
empty collection and unavailable-port outcomes are checked. Private JSON:API
responses must contain the actual omitted article UUID and access-control
metadata; the module returns Unknown without claiming vulnerability.

## Reproduction and evidence

Prepare the two checksum-pinned official archives, then run profiles in one
serial guarded invocation. The runner can reuse its metadata cache while still
creating a fresh configuration and disposable project per profile.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/drupal_pgsql/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb drupal_pgsql_private drupal_pgsql_empty drupal_pgsql_disabled drupal_pgsql_unrelated drupal_pgsql_mariadb drupal_pgsql_fixed drupal_pgsql_prefix drupal_pgsql
```

The [shared lab](drupal_pgsql/README.md) documents setup and resource limits.
Read-only per-profile archives live under
`/Users/dwelch/.codex/reports/drupal-pgsql-<profile>-<run>-seal`.
Each retains raw runtime/console/RSpec/native output and exact declared input
copies. Their manifests are fully rehashed and their file sets checked:

| Profile | Entries rehashed | Manifest SHA256 |
| --- | ---: | --- |
| `drupal_pgsql_private` | `114` | `9ca2f9a48ada322cab547b2fd6f505e38610321681007c7ef37b7f45c138ce2d` |
| `drupal_pgsql_empty` | `114` | `4930984aa06ff370687f8689add9e4e805d95107e1c63de98e8738f28b2e76aa` |
| `drupal_pgsql_disabled` | `114` | `dbbc407b2fb481cf10de0b0b6f86f219da3ea46b6a7b039d86d4f69171c217d3` |
| `drupal_pgsql_unrelated` | `113` | `e1410fbb79a622fce401923749e855c66edca11651e567600c4998bd2d6ee9ef` |
| `drupal_pgsql_mariadb` | `117` | `7ecd3a2a8421f77b22488e78cf8cd2b4dbb681cb58552afde8330ff03adb1e1f` |
| `drupal_pgsql_fixed` | `116` | `d0abee37b9e7b2f1da3e245991afb2d224f8a3b647c13ebe04ccfdabeae2dec2` |
| `drupal_pgsql_prefix` | `116` | `47001fe13fda9e472b674e06aa140ee6407697a90cc1ab95e8c66b152b486151` |
| `drupal_pgsql` | `122` | `4f3c45f6ec91fbca26c350c561d6c975117721dca05b7034f3e64040a1ee82c2` |

All 104 union declared inputs still match. The final checkpoint
archive is `/Users/dwelch/.codex/reports/drupal-pgsql-qualified-checkpoint-20261116`.
The handoff records its manifest hash and the one-time count application.
Previous publication CI results are recorded separately in the
[follow-up journal](VERIFICATION-20261116-publication-followup.md); their native
jobs' actual upstream Framework checkouts do not qualify this module's bytes.
The broader campaign and the recorded CI investigations remain open.
