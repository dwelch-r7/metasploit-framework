# Bounded Drupal 7 regression qualification

All ten bounded Drupal profiles pass **26 original cases and 41 public module
calls**. Twenty sessions were used to create fresh `www-data` files and explicitly
closed: twelve plain PHP shells, six native Linux shells and two staged PHP
Meterpreter sessions. Ten finite Unix commands also passed with fresh file proofs.
The owning module is unchanged. This is a replay of existing coverage after the
PHP payload repair and container-limit adaptation, not 26 newly added cases.

## Actual profiles

Use the [component guide](drupal7/README.md) and guarded runner. Genuine Drupal
7.57 and 7.58 installations run on PHP 5.6.40 with their real standard profile,
MySQL driver and bundled File module. The unrelated control is genuine Apache.
Every profile starts at most three containers and completes teardown before the
next profile starts. The earlier eight-container topology is no longer needed.

| Profile | Cases | Public calls | RSpec seconds | Actual run |
| --- | ---: | ---: | ---: | --- |
| `drupal7` | 7 | 11 | 115.6 | `20261115T142541-66cdec` |
| `drupal7_prefix` | 3 | 5 | 107.3 | `20261115T142843-66b5ad` |
| `drupal7_assert_off` | 2 | 3 | 105.5 | `20261115T143211-110123` |
| `drupal7_no_changelog` | 2 | 3 | 59.0 | `20261115T143538-eeef0b` |
| `drupal7_fixed` | 3 | 3 | 57.3 | `20261115T143728-30020e` |
| `drupal7_unrelated` | 2 | 2 | 51.1 | `20261115T143935-3aaa02` |
| `drupal7_php` | 2 | 4 | 132.6 | `20261115T141326-792acd` |
| `drupal7_php_prefix` | 2 | 4 | 133.6 | `20261115T141639-64b36b` |
| `drupal7_php_assert_off` | 2 | 4 | 142.3 | `20261115T142004-2151b5` |
| `drupal7_php_staged` | 1 | 2 | 77.7 | `20261115T142325-5f2f26` |

All reports have zero failures, pending cases and outside errors. RSpec durations
include native controls and console interaction; image setup is separate. The
runner can execute selected profiles serially in one invocation, retaining its
metadata cache. A single profile is enough for a targeted path check.

The actual 26 runtime example descriptions exactly match the original command-19
and PHP-7 multiset. No original case body, assertion, two-run loop or recovery
helper was removed or replaced. A component-owned table scopes the actual
services, native callbacks and exact description filter. Collection checks also
verified that an unrelated example group remains selected.

Independent native controls inspect versions, source, accounts, paths, database,
assertion and changelog policy. Real anonymous password forms and administration
refusals establish application behavior. Repeated form-based execution creates
fresh files as `www-data` on affected installations and proves its absence on the
fixing release. Eight actual callbacks from the selected vulnerable profiles
reach a standard Ruby TCP listener inside Framework. Missing paths and unrelated
HTTP remain distinct negative controls; no replacement application route or
synthetic vulnerability response is installed.

The owning paths cover automatic and explicit target selection, check results,
missing installation and changelog handling, AutoCheck-disabled initialization,
the configured system function, PHP memory/dropper delivery, Linux executable
delivery and staged PHP sessions. Successful changes repeat twice. Artifact
absence is asserted before failed-case recovery; recovery cannot make a failed
cleanup assertion pass. Checks on the fixing release and unrelated server also
refuse execution without creating the proof file.

## Payload repair and execution limits

The [WordPress checkpoint](VERIFICATION-20261115-wordpress-admin.md) established
an empty-command `ValueError` in `php/reverse_php` on PHP 8.3.28 and a narrow repair
in its generated command wrapper. These Drupal runs verify that repair on the
legacy PHP 5.6.40 consumer, including root, prefix and assertion-disabled paths.
The repaired payload SHA-256 is
`1a38a7d8eed0ca7275b24a866aac70540b4fd2409b42d1d04f05a3f8ab674aba`.

The unchanged Drupal owner SHA-256 is
`55b107e5f7ad9ab232714235b37d687e4e3c09e07261e6e73c27043473a9cd84`. Its whole module guide
and human console scenarios remain unchanged. Fixture integration is commit
`7c58845b344`; the Apache PID-cap correction is `50eb3d9ca1f`.

PHP 5.6 rejects Drupal's array argument as the assertion description, so these
installations exercise the module's existing PHP CLI fallback. Memory/dropper
labels describe the declared delivery targets; these results do not qualify the
in-process assertion path. The staged CLI case passed both executions, while the
WordPress Apache cases remain interrupted and unqualified after second-run
reconnect bursts. The applications, PHP versions and delivery/SAPI paths differ;
this is not a controlled PHP-version comparison and establishes no initiating
bootstrap cause. Drupal 8, other runtimes, architectures, databases, TLS and
restricted webroot variants remain separate targets.

## Resource and verification evidence

Resolved configuration and all 29 retained container inspections match the
intended CPU, memory, PID and init settings. Applications use 0.5 CPU, 384 MiB and
128 PIDs; MariaDB uses 0.5 CPU, 512 MiB and 128 PIDs; Framework uses one CPU,
1536 MiB and 256 PIDs. Unrelated Apache uses 0.25 CPU, 128 MiB and 128 PIDs. No
inspected container had its `OOMKilled` flag set. These Drupal profiles do not
claim the per-phase cgroup-counter observations collected by the WordPress hook.

The Apache cap was corrected before this replay because the matching WordPress
control demonstrated that event MPM exhausts 64 PIDs during ordinary startup.
The later 128-PID configuration and genuine Drupal unrelated-control run passed.
No module assertion, counter requirement or production source was weakened.

Four fixture Ruby files passed strict RuboCop and syntax checks. Thirteen actual
host collection runs checked the original two modes, ten partitions and an
unrelated-group sentinel; they are collection evidence, not additional functional
cases. Ten actual Compose configuration checks verified roles, limits, mounts,
build paths and version pins. The original preflight seal is
`drupal-bounded-profiles-preflight-20261115`, manifest SHA-256
`0950e8ee53e28146a88743984844a7cb74530712958e7f3702255990331845a8`.
A separate current configuration check and actual inspections retain the Apache
128-PID correction.

Each completed profile passed six independent parent Docker queries and a
released-lock check. All known container IDs, network IDs and volume names were
absent, and the global container inventory was empty between profiles. Local
exports under `/Users/dwelch/.codex/reports/` include the actual run and all 64 or
66 declared inputs, native requests, commands, console output and exact cleanup.

| Export directory | Manifest SHA-256 |
| --- | --- |
| `drupal7-command-root-qualified-20261115` | `be8ee7774e4fbabf20164f72073499271ff9d157d9eaf4f9f1e4264d55730a4a` |
| `drupal7-command-prefix-qualified-20261115` | `d9cb6a42ff816bee9d3bb8b53289771a7f81464bdde0753bceb5745a2c0e7123` |
| `drupal7-command-assert-off-qualified-20261115` | `10d5da3e76ac17ac9e3529ab9f5bd831944e7e2866163d51363588fabd1c48a9` |
| `drupal7-no-changelog-qualified-20261115` | `3c18552e8395c5eccaa0afcebf19c331b11d204a40912d8b1819a28ed250efc2` |
| `drupal7-fixed-qualified-20261115` | `f93b404f4640ce545533e38c462fcf6beb6680def685169e4edfbb89f98d65d2` |
| `drupal7-unrelated-qualified-20261115` | `de81336ce6e87bb241661318060c1de80c6866f24d0d55a467aa7818ebdae289` |
| `drupal7-php-root-qualified-20261115` | `e83d67762902deef0d55c6b9aeaeb299264f713c657aa01c2ca9ef8e765adc56` |
| `drupal7-php-prefix-qualified-20261115` | `e6694d55639abf896c0daa64eb0a0133652d0286fe12c1c273227fe1c7a2dd8c` |
| `drupal7-php-assert-off-qualified-20261115` | `462d0042ae01bae38394170190551fa26213cdb714040a48e53cc8d0800b7147` |
| `drupal7-php-staged-qualified-20261115` | `6641e22dd9e4437cf91cb606d8bc12a7601d251da8d09d4fa06682105aa21316` |

The combined WordPress/Drupal audit verified 14 passing profiles, 49 cases, 70
public calls and 28 used/closed sessions. Two WordPress staged profiles remain
unqualified with null completed counts. Twenty selected functional, isolated-PHP
and preflight exports were rehashed: 2,452 file entries matched their manifests.
A focused default-CI invocation passed nine payload-generation examples plus
seven existing datastore-formatting support examples; it excluded both functional
bridges. Neither support examples nor the temporary 38-case PHP matrix inflate
these functional-case totals. No full local RSpec suite was run.

## Recorded campaign checkpoint

Recorded qualification advances from 248 owners / 327 profiles / 3,068 cases to
**249 owners / 339 profiles / 3,091 cases**. WordPress adds one owner, four passing
profiles and 23 distinct cases. Drupal replaces its two historical profiles with
ten bounded profiles while retaining the same 26 cases and one existing owner.
The two interrupted WordPress staged profiles add no qualification. Other
families retain their own frozen inputs and scope; no whole-campaign replay or
completion is claimed. The new reusable standalone PHP regression target is
still separate work and is not counted here.
