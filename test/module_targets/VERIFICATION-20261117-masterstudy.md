# MasterStudy registration and privilege verification, 2026-11-17

Qualified one owner in seven profiles with **38 passing public cases in one
aggregate with exit 0**, reaching **282 runtime owners in covered paths,
573 qualified profiles and 3,985 historical functional cases**. The broader
campaign remains active. No PR is created.

Owner: `auxiliary/admin/http/wp_masterstudy_privesc`. Two narrow repairs make
generated passwords satisfy the target policy and support the actual WordPress
database table prefix. Root owner commits are `4525c9689b9` and `33cd7920c6d`;
their contracts are separate commits `6b35c0ac3d0` and `7f3c1921e25`.
The exact final tested owner SHA256 is `f9b6532948b16c758ed7e42b2f3c332a8d7535e5ccbc785aa25364f3e4b5d2d3`.

## Reproduction and source scope

See the [target guide](masterstudy/README.md) for preparation, serial profile
commands and limits, and the
[module guide](../../documentation/modules/auxiliary/admin/http/wp_masterstudy_privesc.md)
for operator options. Complete official 2.7.5 and 2.7.6 archives are pinned in
[releases.json](masterstudy/releases.json), with 1,573 installed-file hashes each.
Both archive CRC/path/symlink checks and actual installed-file comparisons pass.

The [CVE-2022-0441 CNA](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2022/0xxx/CVE-2022-0441.json)
identifies the original before-2.7.6 administrator-registration issue. The
database-prefix and password repairs here address module behavior; they do not
extend that advisory's affected interval.

The selected images declare Linux/amd64 and pin WordPress 6.8.3, PHP 8.3.28 and
MariaDB 11.2.2. WordPress uses ordinary application grants. An ordinary PostgreSQL
reporting role begins with an empty schema; Framework creates and uses its real
reporting schema. Versions, source, roles, configuration and account state are
independently observed. Vendor PHP, nonce generation and responses are unchanged.

## Confirmed repairs and preserved failures

The actual original blank-password getter can produce `lrMIJLFPAQ`, which lacks
a number. The genuine endpoint rejects that exact value with its number-policy
error, creates no account, and continues to pass normal registration/admin,
repeat, state and resource controls. The repair generates 13 characters with
lowercase, uppercase and a digit, preserving explicit nonblank input and datastore
configuration. Fourteen focused contracts produce **14 examples/5 failures** on
the original and **14/0** after repair. Framework/generators are doubled with
documented output lengths; the real getter/datastore execute. The captured
missing-digit value and synthetic other-category cases are distinguished.

The original sampled public defaults happen to be valid: that corrected
seven-case cohort passes before repair. An unchanged seven-case public replay
also passes after changing only the owner among **111 declared inputs**; the
other 110 remain byte-identical, and actual generated values now have 13 bytes
and usable administrator accounts. This is compatibility evidence, not a claim
of an observed failed sampled public-default run. Contracts are imported after
the owner-only replay.

On a genuine `lab_` installation, the original hardcoded `wp_capabilities` key
leaves subscribers despite registration success. Native controls using the real
`lab_capabilities` key create administrators before and after the owning calls.
The original public cohort is **3 examples/2 failures**. Changing only the owner
among **111 inputs** makes the same three cases pass with two administrators.
New advanced `DB_PREFIX` defaults to `wp_` and supports WordPress prefix
characters, including an empty prefix. Its 14 focused contracts go from
**14/11 expected failures** to **14/0**; the 14 password contracts also pass.
Availability/version, HTTP, UI and reporting are doubled in those prefix
contracts; real check/run, AutoCheck, nonce extraction and request construction
execute. All unit runs have zero auto-loaded support examples.

The first public seven-case attempt has six harness failures: it expected the
literal `Wordpress` service and no login rows. Actual source and PostgreSQL rows
show lowercase `wordpress` and automatically created Untried logins for
service-origin cores. The assertions are corrected; no reporting repair is
claimed. Earlier native failures also preserve a quote-sensitive HTML matcher,
real first-admin initialization and the original fixed-response expectation.

## Selected aggregate

| Profile | Release / condition | Cases | Admins | Subscribers | Core/login pairs | RSpec seconds |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| masterstudy | 2.7.5; DB prefix `wp_` | 19 | 8 | 0 | 8 | 201.7 |
| masterstudy_fixed | 2.7.6; DB prefix `wp_` | 3 | 0 | 1 | 0 | 63.5 |
| masterstudy_subdirectory | 2.7.5; DB prefix `wp_`; URL `/portal` | 3 | 2 | 0 | 2 | 69.2 |
| masterstudy_plain | 2.7.5; DB prefix `wp_`; plain permalinks | 3 | 2 | 0 | 2 | 72.5 |
| masterstudy_no_check | 2.7.5; DB prefix `wp_`; AutoCheck=false | 3 | 2 | 0 | 2 | 68.5 |
| masterstudy_custom_prefix | 2.7.5; DB prefix `lab_` | 4 | 2 | 1 | 3 | 70.3 |
| masterstudy_empty_prefix | 2.7.5; DB prefix (empty) | 3 | 2 | 0 | 2 | 63.3 |

Run `20261117T192618-5862dc` has no failures, pending cases or outside errors,
and all teardowns pass. **20 actual public accounts** comprise 18 administrators
and two subscribers. Passwords, native auth cookies, WordPress role/capability
APIs and actual user-management HTTP access prove each result. Requested explicit
values match the actual invocation; generated values come from its transcript,
not from calling getters again. Repeated runs retain the selected console module
and recover their own target state between executions. No Framework session or
job remains, and no Meterpreter/command-shell qualification is claimed.

The main profile covers individually generated username/password/email and all
defaults, explicit 8/20-character boundaries, username/email collisions, invalid
username/email, rejected 7/21-character passwords, and the original missing-number
value supplied explicitly. Genuine missing-base 404 and 200 WordPress login-page
nonce failures leave no account or credential. The existing check's missing-base
Safe result/reason is recorded; transport-disconnect classification is outside
this qualification. URL subdirectory, actual permalink state, AutoCheck disabled,
custom database prefix and real unprefixed tables are independently exercised.

The two subscriber conditions are intentional, distinct controls. Genuine 2.7.6
raises its logged `default_fields`/`array_column` vendor TypeError after inserting
a subscriber; its login works, administrator access fails and subsequent normal
registration works. AutoCheck blocks the normal owning attempt; with it disabled,
the module reports the real error and stores no credential. On 2.7.5 with `lab_`
tables, deliberately supplying `DB_PREFIX=wp_` still registers a subscriber with
valid credentials. The generic registration-success message is not privilege
proof; the operator must supply the correct prefix. Neither condition establishes
whole-plugin security or automatic prefix discovery.

Actual PostgreSQL observations contain **19 credential-core/Untried-login pairs**
with exact credential, service, host, port, workspace and module identity; their
last-attempt timestamps are nil. Independently successful native authentication
is separate from that Framework status. The fixed partial subscriber has no
credential record. There are 30 distinct scoped vulnerability rows from
checks/AutoCheck, not that many administrator creations. Loot remains empty.

## State, resources and limits

The owner retains created accounts. All **20 public accounts** are recovered
through native WordPress deletion after ID/name/email/password/session-agent
ownership checks. Baseline users, password hashes/roles/tokens and usermeta,
vendor options/tables, posts, configuration, source hashes and complete upload
trees match selected before/after state. Real frontend/admin warm-up creates a
navigation post and initializes vendor styles, schema and options before that
baseline; those changes remain recorded. Unrelated WordPress options, counters,
logs and complete database restoration are outside the selected-state claim.

The aggregate records **329 native HTTP controls**,
76 actual cookie validations and
84 zero OOM/PID snapshots. One stack runs at a time, with at most
three capped containers totaling 1.75 CPUs/1,408 MiB. Memory/swap, CPU, PID/init,
platform and loopback settings are explicit and verified. All **35 attached
volumes/networks** are individually absent after teardown. No unrelated images
or volumes are pruned. PHP mail transport is explicitly `/bin/false`; no mail
delivery or activation-flow claim is made.

Changed Ruby syntax/RuboCop, owner msftidy, module-guide msftidy_docs, PHP syntax
and all seven Compose/input plans pass. No full RSpec suite is run. Historical
human Scenarios remain byte-identical. Private immutable source/native/unit/
public archives preserve failed attempts, raw CLI/JSON outcomes, transcripts,
125 unique declared inputs, state/resource observations and exact cleanup queries.
Publication CI is separate and does not establish execution of these opt-in labs.

Other plugin/runtime releases, TLS, multisite, CAPTCHA, email activation/
premoderation, other locale behavior and arbitrary vendor-transformed password
inputs remain unqualified.
