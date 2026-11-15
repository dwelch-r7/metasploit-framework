# WPS Hide Login discovery qualification

All six profiles pass **eight functional cases and fourteen public scanner
calls**. The repaired module reveals the independently configured working login
at the root and refuses the non-login redirect in a subdirectory. Fixing-release,
absent-plugin, unrelated-server, missing-installation and native closed-port
controls pass. This adds one runtime owner and six profiles.

## Real targets and outcomes

Use the [component guide](wps_hide_login/README.md) and guarded runner. Genuine
WordPress 6.8.3/PHP 8.3.28 runs checksum-pinned official WPS Hide Login 1.9 and
1.9.1 releases. The shared fixture installs/activates the real plugin through
WordPress APIs, stores distinct hidden slugs and inspects the installed source,
readme, activation and configuration. No application route or vulnerability
response is substituted. The unrelated control is genuine Apache.

| Profile | Cases | Public calls | RSpec seconds | Actual run |
| --- | ---: | ---: | ---: | --- |
| `wps_hide_login` | 3 | 4 | 57.0 | `20261115T161921-cddfae` |
| `wps_hide_login_prefix` | 1 | 2 | 50.9 | `20261115T161752-5c1332` |
| `wps_hide_login_fixed` | 1 | 2 | 51.6 | `20261115T162124-07d6d4` |
| `wps_hide_login_fixed_prefix` | 1 | 2 | 48.8 | `20261115T162300-e563c0` |
| `wps_hide_login_absent` | 1 | 2 | 49.3 | `20261115T162443-ca39d9` |
| `wps_hide_login_unrelated` | 1 | 2 | 47.5 | `20261115T162632-606170` |

Every report has zero failures, pending examples and outside errors. Durations
include cold console startup and native controls; image/setup time is separate.
The documented command runs selected profiles serially in one guarded invocation
and can reuse its metadata cache. A targeted profile can be run independently.

The root success case runs twice. Each reported URI must match the target
scheme/authority, the independently stored slug and native expected path; a
separate HTTP request must return the real login form. Each negative profile
also invokes the scanner twice. Native controls confirm that fixed-release
secret forms remain available, so version-guard refusals are not attributed to
a broken application. Thirty-four native HTTP requests and before/after CLI
inspection establish target prerequisites and unchanged plugin/configuration
state. No sessions or background jobs remain. Ordinary audit logs are retained.

## Original failure and repair

Original public run `20261115T155619-dc4d97` reports
`Login page: http://<target>/wordpress/404/` despite the native destination
returning 404 without a login form. Its one case fails after one public call;
native controls, resource counters, state preservation and teardown all pass.
A separate original-root run passes three cases/four calls and confirms genuine
disclosure. Both originals are sealed before source changes, rather than
classifying every failing assertion as a module defect.

Four native-only comparisons independently distinguish affected-root disclosure
from affected-prefix and fixing-release concealment redirects. The 1.9 plugin
has a literal `/wp-admin/options.php` exception, explaining its root/prefix
difference. A vulnerable version alone does not prove that a returned Location
is a working login. The original source accepts any HTTP 302 Location.

The separate-worktree repair `65c92a28883` integrates as `76bb7e2da6c`. It uses
existing HttpClient URI/origin/redirect helpers, verifies with GET and permits
one same-origin canonical redirect. Success requires a structural WordPress
POST authentication form, with username/password/submit fields and a permitted
form action. It preserves query bytes, relative paths, VHOST and operator
settings, distinguishes missing/refused/error responses, and handles expected
TLS errors. It does not depend on an English label, a particular slug, core
IDs/classes or the literal `/404/` path.

Original owner SHA-256:
`cf0e23084f88d35da4dd2286627bbd0801ca437e1cdded439cd94d23e28d6ab9`.
Repaired owner SHA-256:
`a39fd4c0223f700ce8bbb16875240d0855e3edb2e39367398e3a2bd22cee19c4`.
The complete original module guide and human Scenarios are byte-identical.

The identical final focused suite/seed 7721 reports **39 examples, 30 failures
on original source, then 39 examples and zero failures on the repair**. HTTP and
passive-discovery boundaries are doubles; Rex responses, HTML parsing, redirect
resolution/origin policy and expected connection-error handling remain real.
Fixtures derive from the captured real forms/concealment page, with documented
extraction and TEST-NET-1 origin replacement. Synthetic URI, status and form
variants are explicitly identified. Thirty contract differences are not thirty
separate native defects or additional functional cases.

Earlier fixture-path constant and scanner-exception expectation errors remain
separately recorded as harness failures. Some transient intermediate spec bytes
were not saved; the export explicitly discloses that limitation instead of
reconstructing them. Final original/fixed inputs and process receipts are sealed.

## Resources, cleanup and retained evidence

Each application stack uses three capped containers; unrelated HTTP uses two.
WordPress uses 0.5 CPU/384 MiB/128 PIDs, MariaDB 0.5 CPU/512 MiB/128 PIDs,
Framework one CPU/1536 MiB/256 PIDs and Apache 0.25 CPU/128 MiB/128 PIDs. All use
init. All seventeen actual inspections match the intended roles/limits and have
no OOMKilled flag. Before/after cgroup observations have zero OOM/PID-limit
counts for every role; memory-boundary max events remain informational.

Six independent parent queries per final profile pass: **36 cleanup queries and
six released-lock checks**, verifying all seventeen exact container IDs, six
networks and ten volumes are absent, with an empty global inventory between
stacks. Each next stack starts only after teardown is verified. All sixty
recorded source/fixture inputs per profile match the final checkout.

Strict RuboCop, msftidy, syntax and diff checks pass for the repair. Three new
fixture Ruby files also pass strict RuboCop. A primary-checkout default-CI check
passes 55 examples: 39 owner regressions, nine payload-generation examples and
seven existing datastore-formatting support examples. It excludes all four
selected functional bridges and performs no native capture. No full local RSpec
suite was run. The [preceding publication CI report](VERIFICATION-20261115-php-publication.md)
records its exact checkout and two upstream native time limits separately.

Local read-only exports under `/Users/dwelch/.codex/reports/` retain actual run
JSON, requests, console output, commands, exact teardown and frozen inputs. The
six current final exports contain 662 rehashed file entries.

| Export directory | Manifest SHA-256 |
| --- | --- |
| `wps_hide_login-20261115T161921-cddfae-sealed` | `4d86f8df9f6a86688960316fca6ab2932e522014ec2f2527837c4ef633467a52` |
| `wps_hide_login_prefix-20261115T161752-5c1332-sealed` | `f3d5b3cb81dbae8a9142c32f5d6bba013d91f871ad9be8ccf7e028f4a32ac182` |
| `wps_hide_login_fixed-20261115T162124-07d6d4-sealed` | `14980068c362fcd57e9d6ceb69940e6fc3363dc250d6be5d51de99f10e5d7383` |
| `wps_hide_login_fixed_prefix-20261115T162300-e563c0-sealed` | `9245b6e057b6e490df9d1642ae9a4672aa1b277a13010b421448224a53dc825a` |
| `wps_hide_login_absent-20261115T162443-ca39d9-sealed` | `96ef612874d617bc7fc0334d9a8cd711e506610e198fe0ea8c7167198a68a839` |
| `wps_hide_login_unrelated-20261115T162632-606170-sealed` | `758c9ed547e442b26d44d1e90d3aca5cb5bbe1be55da167b8171f4670170b022` |

The source repair export `wps-hide-login-redirect-repair-20261115` contains 68
independently rehashed entries. Its `MANIFEST.sha256` hash is
`9cacc509d8709e44c4c42d82be2e7371d3d724fe7455db8f6e4fed3949de06af`.
The original prefix failure export has manifest
`3f0f475fbb2e06476fb28be0a0313a21de081247aaa0d5138a0f572a03722775`;
the original-root baseline has
`68a917193a0cbfb37129146161fe352b50b6bfc0ac88f8c8bf05aa8e2e0d5d58`.
Four additional native-only exports remain separate and add no qualification.

## Recorded campaign checkpoint

Recorded coverage advances to **250 runtime owners in covered paths, 346
profiles and 3,137 functional cases**. This adds one owner/six profiles/eight
cases to the standalone PHP checkpoint. Focused unit examples, native-only
comparisons and superseded original-root cases are not added again. Earlier
families retain their frozen inputs; this is not a whole-campaign replay or
completion. TLS, multisite, other core/plugin/PHP releases and architectures
remain outside this component's qualification. The separate staged PHP
Meterpreter reconnect investigation remains open. No PR is created.
