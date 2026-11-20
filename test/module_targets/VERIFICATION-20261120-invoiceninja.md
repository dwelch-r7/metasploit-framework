# Invoice Ninja native execution and release controls

The maintained candidate replay passes **33/0** across nine profiles. Invoice
Ninja adds one runtime owner and two qualified profiles with **13/0**, reaching
**316 runtime owners in covered paths, 664 qualified profiles and 4,758 historical
functional cases**. The twenty InvoiceShelf regression cases add no duplicate
campaign counts. Ninja session/default-payload delivery remains unqualified.

## Genuine targets and prerequisites

The two-service fixtures use official Linux amd64 images:

| Release | Pinned image manifest | Installed runtime |
| --- | --- | --- |
| 5.10.10 | `sha256:1999d70953484cc49a3c9386ac8d8a6e8b2730c0302b9901ac14a074f7038fc9` | PHP 8.2.21, Laravel 11.15.0 |
| 5.10.11 | `sha256:292ac305f2cec477870eb4973cf11f8d24879058154573bf1b2cef5d84f81684` | PHP 8.2.21, Laravel 11.15.0 |

Both use the pinned MariaDB 10.6.19 service, genuine migrations/seeder and
`ninja:create-account`. Migrations alone leave zero users and an unready login;
the application's own account command restores HTTP 200. An earlier SQLite
migration fails on MySQL prefix-index syntax. These are retained setup failures,
with no Framework module invoked and no vendor patch applied.

Before/after controls verify seventeen installed files, real database/account
state, the live route collection, HTTP version and independently decrypted XSRF
cookie. The patched image comments out `route/{hash}`; its live route is absent,
login remains healthy and independently generated commands are denied twice.
This agrees with the [original advisory's fixed release](https://www.synacktiv.com/advisories/invoiceninja-unauthenticated-remote-command-execution-when-appkey-known).

The installed PHP serializer and Laravel encrypter construct native command
controls. The generation process must leave its proof absent; only the real
HTTP request may create the exact file bytes as UID 1500. Stock `php/exec`
programs also execute directly as a single PHP CLI argument before PHP owner
attempts, separating interpreter readiness from shell delivery. No private
payload runtime patch, replacement backend response or fabricated check is used.

Run the [maintained profiles](invoiceninja/README.md) with the guarded launcher.
Only the app and database run: 1 CPU/1024 MiB/128 PIDs plus 0.5 CPU/512 MiB/128
PIDs, with equal swap caps. HTTP binds loopback; the database has no host port.
Namespaces, ownership labels and ensure cleanup cover containers, both networks
and the project database volume. Stacks run serially.

## Confirmed source failures and repairs

The initial owner profile records **9/2**, while the shared-helper InvoiceShelf
regression passes **8/0**. Repeated Unix ASCII, Unicode, LF/CRLF and quoted commands
work. Both real PHP owner attempts fail to create their proofs, with PHP parse
errors in backend logs. The stronger profile adds direct stock PHP controls and
owner wrong-key denial: **10/2**, with both interpreter controls passing before
the same two owner failures. The actual serialized string lengths are valid;
the working Unicode owner path does not justify a speculative length repair.

The PHP delivery string used shell double quotes without protecting backticks
inside the standard payload's fallback expressions. The shell substitutes those
expressions before PHP sees the program. Stdlib `Shellwords.shelljoin` now passes
the entire program as one POSIX shell argument. Targets, options, defaults and
the Unix command path retain their behavior. Root commit: `2a8fc3ae694`.

The genuine patched target exposes a separate failure: `checkCode::Safe` raises
`NameError` in direct check and AutoCheck. The corrected fixed-profile oracle
distinguishes AutoCheck's wrapper from the actual owner's exploit body. With
that oracle unchanged, the original source records **3/2**, with healthy login,
route absence and repeated native denial. The one-token `CheckCode::Safe` repair
returns the existing reason-bearing result. Root commit: `3ca38dec802`.

Two focused suites use explicit HTTP/payload doubles, real cookie crypto and a
real POSIX shell argument recorder. The final PHP fixture is actual local
`msfvenom -p php/exec -f raw` output for the observed command; its generator and
native response provenance are retained. A preliminary lexer reconstruction was
found to be damaged during review and superseded before publication.

Identical final inputs give **14/4 to 14/0** for quoting and **14/2 to 14/0** for
the check contract, each including seven support cases. They cover stock PHP,
backticks, dollar/quote/backslash bytes, Unicode/newlines, repeat use, Unix
passthrough, vulnerable/fixed version fields, both lower boundaries and missing
or unsuccessful responses. The root combined run passes **21/0**: fourteen
focused cases plus seven support cases, without pending or outside errors.

Module/spec syntax and new/changed helper/spec lint pass. The module retains two
inherited default-payload offenses, matched against original cop/source lines:
RuboCop exits 1 and msftidy exits 2, with zero new offenses. Metadata is preserved.
The module documentation passes tidy; the 3,426-byte historical human Scenarios
body is unchanged (`61f07e85ffa7fec0d22f5884b24a1abf3bcccd8e2d7fc343cc7d88b5c923d71d`).

## Final maintained replay

| Profile | Examples/failures/pending |
| --- | --- |
| `invoiceninja` | 10/0/0 |
| `invoiceninja_fixed` | 3/0/0 |
| `invoiceshelf` | 8/0/0 |
| `invoiceshelf_file_sessions` | 2/0/0 |
| `invoiceshelf_named_cookie` | 2/0/0 |
| `invoiceshelf_custom_cookie` | 2/0/0 |
| `invoiceshelf_cookie_domain` | 2/0/0 |
| `invoiceshelf_bash` | 2/0/0 |
| `invoiceshelf_php_shell` | 2/0/0 |

No examples are pending and no errors occur outside examples. The unchanged
fixed-profile baseline changes from **3/2 to 3/0** with only the owner source
changed among its declared runtime inputs. The stronger vulnerable baseline
changes from **10/2 to 10/0**; its separate editorial README delta is disclosed
below. Fourteen owner commands preserve exact physical bytes and UID 1500,
including first/repeated PHP runs. Four stock PHP CLI controls pass; seven
selected console objects retain their identities across each pair. An independent
artifact audit verifies 33 positive native/CLI/owner file observations.

The InvoiceShelf cases guard the shared native serializer, command transport and
non-mutating observation helpers on Laravel 10 as well as Laravel 11. All six
real shell sessions (four owner and two independent handler controls) are used
and closed. The audit verifies their physical proofs, PID/birth/socket state,
original reporting-row closure and repeated selections.

All **74 recorded input files remain unchanged** through the final replay.
All **34 recorded memory/PID event captures are zero** and all **26 exact Docker
objects are independently absent** after cleanup. No more than two capped
containers run at once. The final global running/stopped container inventory is
empty. Two unused MCP service containers that appeared during tool initialization
were also removed under the user's broader cleanup instruction.

## Retained evidence

Capsules are verified local evidence bundles; their checksums identify the raw
captures, complete logs, input snapshots and cleanup receipts.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `invoiceninja-maintained-20261120T214245` | 364 | `52848ebbeca99f10d65775cb82e1e12f0418b1d3b586d7626f16c3b60e7db6b1` |
| `invoiceninja-original-commands-20261120T211528` | 126 | `a460af45a3e09b04260b1d50bf493b2ee0b4398332188a2f6f31187e433c6664` |
| `invoiceninja-native-gated-original-20261120T212844` | 110 | `8c303ae248326a8892b2a54a2b6a36296edc69c0cc8c3854161d7ac6377a92d7` |
| `invoiceninja-fixed-check-original-20261120T213517` | 69 | `803c78e5e10828d95f9046bcbeff56e677c411503194d5e30ac0a0e2acec0ae3` |
| `invoiceninja-php-command-quoting-20261120T213658Z` | 65 | `ac4d01c2a49f983a20dbeef81fb7337eb9db60dbcdf41d389ee66f6ab001013b` |
| `invoiceninja-check-contract-20261120T213945Z` | 35 | `ca4da2ddbdb9bb1e7164800a066c1d63cc68e4bf48f07e721b122ffab3164b57` |

The 10/2 baseline retains one README-only editorial change during the run; all
33 other recorded inputs are unchanged. Its snapshot and explicit delta are
preserved rather than claiming full input immutability. The original 3/2
fixed-profile replay verifies every recorded input unchanged. An interrupted
helper-interpolation attempt has no module verdict and adds no counts.

## Self-review

**Summary:** Both confirmed repairs pass focused regressions and genuine native
qualification, with the shared-helper regression passing in full. The broader
goal remains active and no PR is created.

**What looks good:** Installed-class controls, real PHP interpreter execution,
physical bytes/UID and real patched route absence distinguish target prerequisites
from owner errors. Shared helpers preserve the separate application protocols.

**Concerns:** Ninja session/default-payload delivery, other operating systems,
nginx/FPM, TLS, alternate ciphers and other releases remain unqualified. The two
inherited module lint offenses remain. Historical InvoiceShelf Meterpreter
readiness/default-owner failures remain separate and unresolved.

**Suggestions:** Exercise Ninja's real default/repeated session families with
independent native readiness gates before extending its session qualification.
