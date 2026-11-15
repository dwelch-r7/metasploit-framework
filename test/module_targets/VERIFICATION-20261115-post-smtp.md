# POST SMTP account reset disclosure qualification

All seven genuine profiles pass **20 functional cases and 37 public calls**.
Twelve reset URLs have fresh keys accepted by WordPress core, match the actual
SMTP mailbox and plugin database records, and produce byte-exact email-page
loot. Repeated affected paths, the last affected release, a subdirectory,
patched registration, disabled mail logging, an absent plugin and unrelated
Apache are covered. This adds one runtime owner and seven profiles.

## Reproducible targets and outcomes

The [component guide](post_smtp/README.md) provides source preparation and guarded
serial commands. Genuine WordPress 6.8.3/PHP 8.3.28, MariaDB and Exim run official
checksum-pinned POST SMTP 2.8.6, 2.8.7 and 2.8.8. Original plugin REST source hashes
are checked against the pinned archives. WordPress APIs install/activate the
unmodified plugin; no application route, authentication result or mail response
is replaced. Archives stay outside Git in an ignored verified cache.

| Profile | Cases | Public calls | RSpec seconds | Actual run |
| --- | ---: | ---: | ---: | --- |
| `post_smtp` | 4 | 7 | 76.5 | `20261115T173353-14e7a3` |
| `post_smtp_287` | 4 | 7 | 80.3 | `20261115T173604-014b9a` |
| `post_smtp_prefix` | 4 | 7 | 75.5 | `20261115T173803-54447d` |
| `post_smtp_fixed` | 3 | 6 | 53.6 | `20261115T174013-5f7e6f` |
| `post_smtp_no_logs` | 1 | 2 | 50.4 | `20261115T174143-0f1e4f` |
| `post_smtp_absent` | 2 | 4 | 44.3 | `20261115T174312-207761` |
| `post_smtp_unrelated` | 2 | 4 | 38.1 | `20261115T174449-465688` |

Every result has zero failures, pending examples and outside errors. Timings
include native controls and cold console startup; image/setup time is separate.
The recommended multi-profile command reuses metadata within one serial run.
These qualifications each use a fresh guarded invocation/configuration.

Before owner execution, CLI inspection establishes core/plugin versions, PHP
identity, source checksums, active configuration and the owned account. A real
WordPress reset returns HTTP 302; Exim receives the actual message and core
validates its key. Anonymous API controls then demonstrate disclosure on affected
releases or explicit rejection on 2.8.8. Logging-disabled SMTP still delivers
mail while the real plugin log API and database remain empty. In total,
48 separately recorded native HTTP requests support the final profiles.

Success paths execute twice with AutoCheck enabled and twice disabled in each
of the three affected layouts. Each output URL must match the actual authority,
installation path and account, validate through core, match the delivered mail
and new database log, and correspond to exactly the independently retrieved
page saved as loot. A missing user fails before registration/reset. Patched
AutoCheck-disabled registration now fails before changing the reset key, sending
mail or altering plugin/account state. Non-WordPress and plugin-absence controls
refuse execution; neither is counted as successful exploitation.

## Verified source defects and repair

Three original public-console recordings follow healthy native prerequisites:

* 2.8.6 requests a successful real reset but aborts because the shared Boolean
  helper recognizes only HTTP 200. The actual core response is 302.
* 2.8.7 is natively vulnerable, but the original cutoff incorrectly returns Safe
  and AutoCheck refuses execution.
* 2.8.8 with AutoCheck disabled prints successful token creation after the real
  API returns HTTP 200 with JSON `success:false`. It then unnecessarily requests
  a reset: the activation key changes and actual mail/log count increases.

Their recording controllers exit zero because capture/cleanup completed. Their
module outcomes are failures, and they add no passing cases. Each records two
public actions, before/after database/configuration state and exact teardown.
Original source SHA-256 is
`801125921de416245c5ec9164de9ff6b7a957a5386e922f2a017ec6ef3a2179d`;
original helper SHA-256 is
`be2ea70edd25843259e6fb5f80e260e5605bcd2e66945bc9a10d1fe729a16d79`.

Separate-worktree commit `31029079565` integrates as `92d86171e2b`. The helper
retains its Boolean and legacy-200 contract and accepts only a same-origin
reset-confirmation redirect. That acknowledgement alone does not prove delivery.
The owner includes affected 2.8.7, validates the successful registration/token
JSON before reset, and handles absent/denied/malformed/empty logs or missing reset
URLs with explicit failures. The latter preserves saved loot. Expected escaping
TLS failures receive reason-bearing check/run outcomes. No minimum affected
release is inferred beyond the tested releases and documented fixed cutoff.
The [primary disclosure](https://www.wordfence.com/blog/2024/01/type-juggling-leads-to-two-vulnerabilities-in-post-smtp-mailer-wordpress-plugin/)
and original tagged source support the 2.8.8 fix boundary.

Repaired source SHA-256 is
`ff79ed667f843a416137419332dac40aeb5854973f8d3a1c6146785f00e84b60`;
helper SHA-256 is
`6a2bc0e9c4ee61619ccc1e8a0b06ee7ea65878be5f685a0601d8cf3787c92afc`.
The guide corrects the mail prerequisite/version boundary and links the fixture.
Human Scenarios through EOF remain byte-identical, SHA-256
`9e8492c43d01efeb1681808d474e889d20959a4bbcb62cd14d637b6b2604d81c`.

The identical final seed-7721 focused suites report original **15 helper examples /
three failures and 37 owner examples /27 failures**, then repaired **15/0 and
37/0**, all with zero outside errors. HTTP/product/username/reporting/loot
boundaries are explicit doubles; real Rex response/JSON/URI helpers, versions,
AutoCheck and the reset helper execute. Synthetic edge cases are identified and
derive their base responses from real captures. These are not 30 native defects
or additional functional qualifications. Earlier missing-Location guard and
omitted reporting-double corrections retain their exact pre-correction inputs.

Strict owner/spec lint, module tidy, docs tidy, syntax and diff checks pass. The
whole helper retains **29 identical pre-existing strict-lint offenses**, with zero
new offenses and no suppressions or unrelated cleanup. The four fixture Ruby
files pass strict lint. Primary default-CI verification passes 59 examples:
52 focused regressions plus seven existing datastore-formatting support examples,
with this functional bridge excluded. Its private postcheck initially expected
52 and rejected the extra seven; actual RSpec exit zero and all 59 results were
verified directly, without claiming that postcheck succeeded or rerunning the
suite. No full local RSpec suite was run.

## Fixture failures and state ownership

Five initial native-only fixture stops involved loopback publishing on an
internal-only network, legacy mail-address validation, premature mailbox
inspection and Exim working-directory/validated-local-part configuration. Their
source, actual failures and cleanup were sealed before corrections; none called
the owner or qualified it. Three subsequent native-only release comparisons
pass genuine SMTP/key/API/restoration controls independently of the module.

The first functional attempt stops at a wrong native expectation: all actual
releases return HTTP 400 `Auth token missing.`, rather than the expected 401.
It records four failed examples and zero owner calls. The next run reaches
working affected execution but exposes a fixture mail counter resetting per
RSpec example while audit mail is retained, plus Ruby positional/keyword hash
handling. Its four cases/two failures and five completed calls remain separate.
The corrected fixture samples the real mailbox before each success and passes
all final profiles. These failures are not attributed to the module.

Affected registration overwrites the existing connected-device map and server
URL; requesting a reset replaces the account activation key. `CONFIG_CHANGES`
and the guide disclose this. The module cannot recover unknown prior settings.
After each stateful call, an explicit **fixture operator restore** reinstates its
owned password/activation/configuration baseline and verifies equality. Each
emitted key becomes invalid after restoration; actual mail and audit records are
retained until teardown. No account password is submitted or changed, and this
manual restoration is not described as module cleanup.

## Resource limits, cleanup and retained evidence

A normal stack has three capped containers: WordPress 0.5 CPU/384 MiB/128 PIDs,
MariaDB 0.5 CPU/512 MiB/128 PIDs and Exim 0.25 CPU/128 MiB/64 PIDs. Absence uses
two containers; unrelated Apache uses one at 0.25 CPU/128 MiB/128 PIDs. All use
init. Only application HTTP is published on random loopback ports; database and
SMTP stay on the internal network, with SMTP external relay denied. Framework
uses the existing host bundle under `nice` with an isolated configuration;
its memory/processes are outside target cgroups.

All eighteen actual container inspections match their limits and have no
OOMKilled flag. Before/after counters are zero for OOM/PID limits in every role;
memory-boundary max events remain informational. Empty console sessions/jobs,
**42 independent cleanup queries and seven released locks** verify eighteen exact
containers, thirteen networks and twelve volumes absent. The global container
inventory is empty between stacks and after the final run. Each of seven recorded
input maps matches current source, including the verified cached archive where
used; earlier families retain their frozen inputs.

Read-only exports under `/Users/dwelch/.codex/reports/` retain 695 rehashed
final file entries, including actual HTTP, MIME/CLI/state, console, result,
resource and cleanup evidence plus frozen inputs.

| Export directory | Manifest SHA-256 |
| --- | --- |
| `post_smtp-20261115T173353-14e7a3-sealed` | `0218af8dac184c9bc42bee68c976b90d605ab87d3adf66a46fc65f44544aa090` |
| `post_smtp_287-20261115T173604-014b9a-sealed` | `ea4c6c0181a200292f6818a9f8b43faec8e4fe84ace57ddebd71cd71f8f018f9` |
| `post_smtp_prefix-20261115T173803-54447d-sealed` | `8ba7bf3beeeb526b84482cb9c1cab02ac1f841257dabc50c3c1410b75a173892` |
| `post_smtp_fixed-20261115T174013-5f7e6f-sealed` | `62db9e35257bff8f07b6d42835706e2be037e99a1da3fb87f86d0760b030a98b` |
| `post_smtp_no_logs-20261115T174143-0f1e4f-sealed` | `23636e2ef891f32274652369715537c5a03f9588e181d56cbdc5dce3e14b1435` |
| `post_smtp_absent-20261115T174312-207761-sealed` | `9314bd68a54d7b93e945f300cbcad2d36a80f147057b0ce575300f31282d1079` |
| `post_smtp_unrelated-20261115T174449-465688-sealed` | `1f40e924633c306588851f6c2edc7edbe027ee17ecd63e13ec628feff84aea1f` |

The source-repair export `post-smtp-response-contracts-repair-20261115` contains
155 independently rehashed entries and 22 frozen inputs per phase. Its
`MANIFEST.sha256` hash is
`b8d339c84159afd1f1c786e0a810b228e6680dcbd3efa00e6172d38a471a1b7b`.
Original owner recordings, native fixture predecessors and both functional
fixture failures remain separately sealed and uncounted.

## Recorded campaign checkpoint

Recorded coverage reaches **251 runtime owners in covered paths, 353 profiles
and 3,157 functional cases**. Only this owner's seven final profiles/twenty cases
are added; repeated calls, native-only comparisons, focused unit cases and failed
predecessors are not recounted. This is not a whole-campaign replay or completion.
TLS, multisite, an existing mobile authorization nonce, other runtimes/releases
and database-reporting integration remain separate coverage. The broader
inventory and staged PHP session investigation stay open. The
[previous published checkpoint's CI](VERIFICATION-20261115-wps-publication.md)
is terminal with 63 checks passing and one skip; its upstream native-job source
is disclosed separately. No PR is created.
