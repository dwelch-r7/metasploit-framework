# Laravel token execution, discovery and default sessions

The latest maintained set passes **25/0** across **nine profiles in three serial
phases**, with **25 real sessions used and closed**. Three new profiles for
`exploit/unix/http/laravel_token_unserialize_exec` add **13 functional cases**
and one runtime owner, reaching **318 runtime owners, 673 qualified profiles
and 4,788 historical functional cases**. Six shared session regressions add no
duplicate campaign counts. The broader module-inventory goal remains active;
no PR is created.

## Genuine application and native prerequisites

The [command fixture](laravel_token/README.md) replaces the application in the
pinned PHP 7.4.15/Apache 2.4.38 runtime with genuine Laravel **5.6.29**. The starter
revision, Composer downloads, complete dependency lock and seventeen installed
application/dependency source hashes are pinned. There are 86 locked packages.
The documented POST route reaches the actual web/CSRF middleware. No vendor
source or payload runtime is patched.

The first build uses Composer 2 metadata and fails during native application
bootstrap with `Undefined index: name`. Laravel's installed PackageManifest
expects Composer 1's package-array layout. Resolving the lock with Composer
2.2.26 and installing it with Composer **1.10.27** restores the genuine consumer
without editing it. That setup failure is retained and supplies no owner verdict.

Independent PHP controls instantiate and serialize the installed gadget classes,
then encrypt them with the installed Laravel Encrypter. Generation must leave
the physical proof absent. The normal HTTP middleware must create exact file
bytes as UID 33 and return a standalone command-output marker. Each proof is
removed and its absence verified before another attempt.

Faker **1.9.2** clears its formatter map during wakeup. Gadget 1 consequently
fails with no physical proof, while its real debug response reflects the command
text. This is a legitimate negative control. Gadgets **2, 3 and 4** independently
execute through the real middleware. The retained native-only pilot also proves
ASCII and Unicode/quoting/CRLF commands for all three working gadgets and rejects
a wrong encryption key.

## Confirmed source repair

The original check treats any response substring containing its random nonce as
successful command execution. On this target it stops at gadget 1's reflected
debug text, despite that gadget executing nothing. Other gadgets genuinely work,
so this observation establishes **false execution proof**, rather than a claim
that this particular target is invulnerable.

The repair requires a standalone nonce output line and continues to gadget 2.
It also returns reason-bearing Unknown when a deserialization POST has no
response. That missing-response guard has focused unit coverage with stubbed
transport; a live dropped connection is not claimed.

The unchanged source-test inputs move from **12/4 to 12/0**: five focused examples
cover captured reflected contexts, actual native output, fallback selection and
the absent response, alongside seven existing support examples. HTTP response
fixtures retain exact captured excerpts and their originating body hashes.
The fix is made in the isolated `laravel-token-check-proof` worktree at
`a1f562755579b261c548cab76cfe5aad50077753`, then cherry-picked as
`6e826456cfcd4eee2a633a9ff9361a514eda7237`.

The real command/check/discovery profile changes from **9/1 to 9/0**. Among its
27 original recorded inputs, only the production owner changes. The successful
check now attempts gadgets 1 then 2 and observes actual standalone output.
Captured command payloads are ASCII-8BIT, including Unicode inputs, so their
observed character and byte counts already agree. No speculative serialization
length change is made.

## Qualified execution paths

| Profile | Examples/failures/pending | Used and closed sessions |
| --- | --- | --- |
| `laravel_token` | 9/0/0 | 0 |
| `laravel_token_perl` | 2/0/0 | 7 |
| `laravel_token_env` | 2/0/0 | 0 |
| `ignition_bash` | 2/0/0 | 3 |
| `invoiceninja_bash` | 2/0/0 | 3 |
| `invoiceninja_php_shell` | 2/0/0 | 3 |
| `invoiceninja_fetch` | 2/0/0 | 3 |
| `invoiceshelf_bash` | 2/0/0 | 3 |
| `invoiceshelf_php_shell` | 2/0/0 | 3 |

The base profile covers exact ASCII, Unicode, LF, CRLF and quoted command bytes;
explicit keys; genuine debug-page key discovery; full-length wrong-key denial;
short-key rejection; and repeated execution on the same selected console object.
It records 34 positive native file proofs and two native denials. Ten positive
owner file observations contain **three copies** of the intended content each:
non-session payloads invoke all four fallbacks, three of which execute in this
dependency tree. Append-only proofs expose all thirty executions.

The [environment-file profile](laravel_token_env/README.md) deliberately exposes
the generated lab-only `.env` as a genuine Apache-served static file. It proves
the configured key is present, calibrates the installed gadgets, then exercises
check and repeated commands with APP_KEY empty. Trace events show three real
environment-file discoveries and no debug-page fallback. Nine positive native
proofs, one Faker denial and two tripled owner proofs establish this path; the
two owner invocations perform six actual command executions.

The [Perl session profile](laravel_token_perl/README.md) independently proves
native HTTP execution, a UID-33 callback and a stock Perl handler session. The
first owner invocation omits TARGET and PAYLOAD; normal Framework selection
resolves target 0 and `cmd/unix/reverse_perl`. The explicit repeat uses the same
selected console object. APP_KEY is supplied. The legacy owner has no AutoCheck
wrapper; its check is exercised separately by the command/discovery profiles.

The legacy fallback loop can produce multiple callbacks before asynchronous
registration is observed. In both final owner invocations all three working
gadgets produce sessions. The test derives the expected callback count from
actual emitted gadget attempts and independently calibrated working gadgets,
then uses and proves **every** fresh session. Six owner sessions and one native
handler session are used and closed. The production exploit loop is unchanged;
its duplicate-callback behavior remains recorded for further investigation.

Each session creates exact physical file bytes as UID 33 and exposes its new
persistent Perl PID/birth identity, established callback socket and original open
reporting row. Perl starts a disposable child shell per command, so the proof
observes the child's parent PID. Public shell APIs close transport EOF, ending
the persistent Perl loop. Checks require all tracked processes/sockets to
disappear, every original row to close, every proof to be removed, healthy HTTP
and restoration of the complete original process set.

## Retained harness failure and input reconciliation

The first maintained eight-profile frame records **23/1**, comprising base
**9/0**, Perl **2/1** and six unchanged session regressions **12/0**. The Perl
failure is a one-session cleanup assumption: the owner opens three callbacks,
the helper proves/closes the first and then incorrectly expects no sessions.
The native handler and first owner session are the two sessions actually used
in that failed frame. Ensure cleanup closes the remaining callbacks, closes all
three owner reporting rows and restores the full baseline. This frame is
retained as a harness failure, not rewritten as a passing owner run.

Only the Perl helper and README change afterward. A fresh targeted Perl replay
passes **2/0** with all seven sessions used and closed. A third phase adds the
environment-file profile at **2/0**. The seven passing profiles from the first
phase keep their current declared inputs. Independent audits reconcile **113
current declared inputs** across the nine latest profile results, physical
proofs, actual session identities, original reporting closure and cleanup.

The shared session helper adds an identity-default owner-option hook. Only the
legacy token adapter uses it to remove unregistered AutoCheck controls and add
APP_KEY. All six existing consumers above are requalified on their normal paths.
No private payload implementation or transport proxy substitutes for an owner.

## Resources, checks and cleanup

Stacks run serially. New command/discovery profiles use one application capped
at 1 CPU, 512 MiB memory/equal swap and 128 PIDs. Perl adds a disposable reporting
database capped at 0.2 CPU, 128 MiB/equal swap and 64 PIDs. Existing Ninja
regressions peak at three capped containers. Published ports bind only to
loopback. Explicit task namespaces, ownership records and ensure cleanup cover
success, failure and interruption.

All **68 qualified memory/PID event captures are zero**. All **37 objects** from
the three maintained phases are absent, including the retained failed Perl
frame. The installer, native trials and original owner reproduction add nine
objects, making **46 newly removed objects**. Rechecking the prior 266 verifies
**312 absent Docker objects** in total. The final global inventory includes
stopped containers and is empty; no owned ephemeral network or volume remains.
No new agent/tool helper container is started in this tranche.

Nine changed/new helper/spec Ruby files pass RuboCop. The owner passes msftidy
and retains the same seventeen inherited RuboCop offenses, with zero new
offenses. Module-document tidy retains its two inherited long-line warnings;
adding APP_KEY documentation removes the missing-Options diagnostic. Its human
Scenarios body remains 1,030 bytes with SHA256
`6bb0ad080ff6a8fd310e25cc1c78f5e5d3406c5bde4d1350d06954f41f669385`.

## Retained evidence

Local immutable capsules under `/Users/dwelch/.codex/reports/` contain raw output,
frozen inputs, independent audits and exact cleanup receipts. Later passing
profiles do not replace the earlier setup, proof or cleanup-oracle failures.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `laravel-token-composer2-bootstrap-failure-20261121t012359` | 42 | `4ed8b75b35d84eff32b618d78d7206898a9e90385ed9b2d25f4fcc2894f7cd3e` |
| `laravel-token-faker-native-denial-20261121t012630` | 56 | `59fa2b45031a962c463fb81d951d23cae9840d97f3586dbdf6edede2ea47aafb` |
| `laravel-token-native-hardened-faker-20261121t013106` | 153 | `3f0239ff6a0361820878a1db008ec1a0bf29707579099edb8c4b254f56f36b49` |
| `laravel-token-original-owner-20261121T013654` | 165 | `7696c649f66a02c3675ef96a6b4f0ee2e71d3a7c2b4a19660e0f6a37347395bb` |
| `laravel-token-check-proof-source-fix-a1f562755579` | 15 | `5f450e82d4228e9d8f7c22ceeab19300a377d0b5eefff3e8bc80b4617a24477f` |
| `laravel-token-candidate-and-perl-oracle-20261121T015711` | 475 | `21898bc9388178f38e85f771ea5ab0c8fdf50c2a551134b1f0272e7d044af2ca` |
| `laravel-token-maintained-20261121T022249` | 103 | `112500170db805cab82f6b387997c42133d9ce5aae31db1346a715575e96d30a` |
| `laravel-token-env-final-20261121T023054` | 96 | `13aa2dfb3c68d3d4bb2392364449d5fccf37989a3ce434b5b03cae09814a6f2e` |

## Self-review

**Summary:** Genuine native controls qualify command, key-discovery and default
Perl paths while repairing a confirmed check-proof defect.

**What looks good:** Captured before/after evidence distinguishes setup, native,
owner and harness outcomes. Exact physical bytes, every emitted callback,
original report closure and complete process/socket restoration are verified.
The six shared consumers remain current after the small session hook change.

**Concerns:** Genuine fixed Laravel 5.6.30 and the 5.5 branch, other releases and
payloads remain unqualified. Multiple owner callbacks are observed and retained.
Previously retained Ignition log-reset and native PHP Meterpreter failures stay
unqualified and are not retried here. A passing Perl or fetch path supplies no
verdict for those families.

**Suggestions:** Add genuine fixed-package native denial controls and investigate
the duplicate-callback behavior separately. Continue valuable container-feasible
owners only after their actual prerequisites pass.
