# InvoiceShelf native commands, sessions and retained failures

Four maintained InvoiceShelf 1.3.0 profiles pass **14/0**, with zero pending or
outside-example errors, after a shared Laravel cookie repair. Six real shell
sessions (four owner, two independent handler) are used and closed. A separate
native staged Meterpreter session is also used and closed; its dependent default
owner attempt fails and remains unqualified. The renamed-cookie owner case and
inline Meterpreter prerequisite also remain failing.

| Profile | Actual result | Disposition |
| --- | ---: | --- |
| `invoiceshelf` | 8/0 | Check, exact command bytes, PHP command payload, key-file selection, native wrong-key denial and repeats |
| `invoiceshelf_file_sessions` | 2/0 | Genuine file-session mitigation and repeated owner refusal |
| `invoiceshelf_bash` | 2/0 | Independent Bash handler and two used/closed owner sessions |
| `invoiceshelf_php_shell` | 2/0 | Independent PHP shell handler and two used/closed owner sessions |
| `invoiceshelf_named_cookie` | 2/1 | Native execution passes; hardcoded owner cookie name fails |
| `invoiceshelf_php_staged` | 2/1 | Native session passes; actual default owner attempt fails before proof |
| `invoiceshelf_php_inline` | 1/1 | Native readiness fails; dependent owner withheld |

The first four profiles add **one runtime owner in covered paths, four qualified
profiles and 14 historical functional cases**. Campaign totals become **315
runtime owners, 659 qualified profiles and 4,739 historical functional cases**.
The other profiles and every pilot add no qualified counts. Across the complete
maintained run, 19 examples execute with three failures and zero pending/outside
errors; the inline cleanup gate stops its second declared case.
Reproduce with [the target README](invoiceshelf/README.md).

## Target provenance and prerequisites

The historical module documentation's `invoiceshelf/invoiceshelf:1.3.0` tag
returned manifest-unknown. That setup failure establishes no module verdict.
The replacement fixture uses the unmodified
[official 1.3.0 release archive](https://github.com/InvoiceShelf/InvoiceShelf/releases/tag/1.3.0),
SHA-256 `a803b3eae0a0e75e366764345bcb5e30a6d556332750ff964e37adb471ba0350`,
including its bundled dependencies and frontend assets. No Composer update or
application/vendor source patch is applied. The archive contains Laravel 10.48.16.

A pinned PHP 8.3.33 CLI base serves the installed application's own Laravel router
with two PHP workers. This controlled test server is supported by the
[PHP manual](https://www.php.net/manual/en/features.commandline.webserver.php);
it does not qualify nginx/Apache deployment behavior. SQLite 3.46.1, the shipped
migrations/seeder and the application's own installation marker/settings APIs
initialize a disposable installation. All ten installer extension requirements
pass. Native HTTP version/login requests and the real Laravel Encrypter and
CookieValuePrefix validate the installation, key and session-cookie chain.

The app runs as UID 33 with 1 CPU, 768 MiB memory/equal swap and 128 PIDs. Command
phases need one container. Session phases add the existing capped PostgreSQL
reporting fixture, giving at most two containers; stacks run serially and are
removed immediately after each phase.

The [vendor advisory](https://www.synacktiv.com/advisories/crater-invoice-unauthenticated-remote-command-execution-when-appkey-known)
describes the known-key/cookie-session prerequisite. The
[2.0.0 mitigation](https://github.com/InvoiceShelf/InvoiceShelf/commit/a64701bda570629757d3dd5a9277584fc0aeb34c)
changes the default session driver to `file`; it does not establish that forcing
cookie sessions on every later release is safe. Those configurations have not
been qualified by this initial command replay.

## Independent native control

Before each owner command, PHP constructs the gadget with the real installed
classes and its native `serialize`, JSON and encryption implementations. The
control verifies that generation itself creates no proof file, submits the
ciphertext through the real `/login` endpoint, checks exact file bytes and UID 33,
then removes and verifies absence of the proof before owner execution. The
serialized object is disarmed before the CLI generator exits. A wrong-key native
ciphertext does not execute. HTTP status alone is never the command oracle.

## Confirmed shared helper defects

The original identical seven-case pilot had **three failures**. Native execution
of the same commands passed first. Physical LF/CR characters were inserted into
JSON strings without escaping, so correctly authenticated ciphertext contained
invalid session JSON. Key-file selection also accepted an invalid entry because
an exception path returned the verbose logging buffer rather than nil. A further
deterministic crypto case demonstrates a wrong key with valid CBC padding;
accepting successful padding alone cannot authenticate a Laravel cookie.

The focused repair uses standard JSON and OpenSSL padding, explicit failure
sentinels, structural checks and the existing Laravel HMAC generator with a
constant-time comparison. It preserves valid CBC cookie formats and public
method signatures. Repository caller search found InvoiceShelf and Invoice
Ninja; other cipher families and external consumers are unqualified.

The same expanded local suite has 35 focused examples plus seven support
examples: **19 original failures, zero candidate failures**. It covers actual
verbose-buffer returns, malformed/UTF-8 key-file lines, tampered/missing MACs,
wrong-key valid padding, Unicode, NUL and line-ending round trips, with real
OpenSSL reference envelopes. Changed Ruby lint and syntax checks pass. The repair
was developed separately on `laravel-crypto-cookie-correctness` and integrated as
`f8f9de2f7f0`; no PR was created.

The native candidate replay changes only the shared helper among the original
recorded inputs. All seven cases pass with zero pending or outside-example errors;
twelve owner command executions repeat successfully. The console-selected owner
object is reused on each repeat and the repeat disables AutoCheck.

## Retained evidence and setup failures

- Original command failure capsule: `invoiceshelf-original-command-failures-20261120T183810`,
  200 files, manifest SHA-256 `8f272c7fb10f894bfa32b93201ad8ce7239b244b096906a423a307d0bc0bf45f`.
- Separate helper repair: `laravel-crypto-cookie-correctness-20261120T190139`,
  21 files, manifest `d0b9be7943a8a957b8555e01b3a9cd6c292be8e0606bb532990b6e630b2d19d5`.
- Corrected native commands: `invoiceshelf-corrected-command-replay-20261120T190213`,
  69 files, manifest `005f3ad919356b439046d59ac25a538cf6ce225203760ce9e3c3f9865a7e8e15`.

The original capsule also preserves a missing-ZipArchive setup failure, a Python
HTTP-helper name collision, and the corrected native controls. Neither setup
failure is a module failure. One initial network-absence matcher failed to
recognize Docker's `network ... not found` wording; an independent follow-up
inspection verified both exact resource IDs absent. Later receipts use the
correct matcher. Candidate command inputs remain unchanged throughout execution,
and its container and network are independently absent afterward.

The original human Scenarios body remains unchanged: 3,600 bytes, SHA-256
`0ac641e7ebd37e95cc28ce78c7d08dae61b2fa9a731494f72e39c7f5c8a11a94`.
No generated console output has been added to that section.

## Session pilot disposition

The first combined session pilot records five examples, three failures and two
pending cases. The staged independent PHP Meterpreter control never reaches a
usable ready event. Asynchronous invalid-session messages from it contaminate a
later inline handler-start assertion, so that inline payload is not generated or
launched. The PHP shell then fails readiness and its cleanup observes a FIN_WAIT2
socket after the original process set returns. Bash is not reached after that
cleanup gate. These outcomes are retained without assigning owner failures.
The capsule `invoiceshelf-first-session-pilot-20261120T191802` contains 81 files,
manifest `1aa5618443c06a85033f6e06d567f43396160783408c6c1bcda88711aa8463d1`.
Its two containers and network are independently absent.

Fresh stacks isolate the next three payload-family controls. Bash and PHP shell
each pass **2/0**, including one independent handler and two repeated owner
sessions. All six sessions perform real public proofs, close their original
reporting records and restore process/socket baselines. The fresh inline PHP
Meterpreter control still produces no usable session; cleanup retains an
established callback, the phase fails and its dependent owner is not invoked.
The initial helper's cleanup exception masks the readiness exception; the
maintained helper records both and preserves the primary exception. No private
payload framing patch is installed.

Those isolated pilots are sealed as
`invoiceshelf-isolated-session-pilots-20261120T192350`: 142 files, manifest
`48550c9a3253e3ace3eef7aa71720474089a960f2676f6ec810ea795e41182cc`.
All nine exact Docker objects are independently absent. They are pilot evidence,
not additional historical qualified counts.

A host dry-run invocation initially referenced the wrong acceptance-helper path.
It failed before any example loaded; the corrected invocation uses the spec's
own require and the established acceptance tag. The functional runner had the
correct invocation throughout. Lint-only preflights also retained and corrected
three harness style offenses; these are not module failures.

## Session-configuration contrast

On the same unmodified 1.3.0 release, `SESSION_DRIVER=file` passes both maintained
cases. Native decryption authenticates the real session identifier; a genuine
Laravel-generated gadget in the paired data cookie is ignored and creates no
proof. The owner still returns version-based Appears, then withholds both command
attempts because the data cookie is absent. This qualifies that configuration's
denial path, rather than a native 2.0 release.

`APP_NAME=InvoiceShelf` exposes a separate confirmed owner defect. Laravel selects
`invoiceshelf_session`; source/installer checks pass, and the independent native
command through that actual cookie writes the expected bytes as UID 33 and is
removed. The module then aborts with `No cookie found. Unable to check APP_KEY.`
because `exploit` searches only for `laravel_session`. The profile records **two
examples / one failure**, with no pending or outside-example error. Its first
owner attempt fails before the requested repeat; neither execution is counted as
a success. The maintained `invoiceshelf_named_cookie` case remains failing for
further investigation. No application patch or invented cookie is used.

The first maintained run was deliberately interrupted before the Bash profile:
recorded console output showed `set TARGET 1` automatically switching to a Linux
fetch payload, while a new fixture branch omitted PAYLOAD and expected Bash.
That would not match the calibrated native handler. The fixture now explicitly
selects Bash; it makes no claim about the Unix target's automatic payload.
The completed command profile had passed 8/0; the file-session profile was only
partly executed. These partial results add no campaign counts. All exact Docker
objects were removed and all recorded inputs stayed unchanged during that run.
Its capsule is `invoiceshelf-interrupted-maintained-20261120T193031`: 125 files,
manifest `e4ac78b32a3948a35430880516f293668a0fcfc64b1b37af503dee24f063eb68`.

## Final maintained evidence

The final replay is `20261120T193335-2c8545`. All **54 recorded input hashes**
remain unchanged throughout the run and match the audit's current inputs. The
installed archive, thirteen genuine vendor/application source hashes, ten
installer extension requirements and seeded database counts verify before and
after each profile. All **22 resource-event captures** pass their OOM/PID-limit
checks. Stacks run serially, with a maximum of two capped containers; all **18**
observed Docker containers/networks are independently absent. An unfiltered
inventory including stopped containers is empty, and no task networks or volumes
remain. The shared namespacing/cleanup policy is loaded before launch and again
before finishing. No PR or external comment is created.

The parent audit matches every successful session to its original open/closed
reporting row, actual payload/owner metadata and target PID/birth/UID. The six
shell sessions restore their complete process/socket baselines; repeats share
the same selected console object. The seventh, independent staged PHP
Meterpreter session also performs its public file/identity proof and closes its
original row. Passive owner tracing then confirms that the first exploit
selection, which omits TARGET and PAYLOAD, actually executes target 0 with
`php/meterpreter/reverse_tcp`. That attempt repeatedly produces invalid sessions
and the console wrapper times out; no owner proof succeeds and the repeat is not
reached. The profile remains failing.

Native PHP controls execute the real cached handler payload through a CLI eval
of an exact hashed file. The module delivers PHP through its existing decoded
stdin pipeline. Together with the earlier independent readiness failures, this
leaves entrypoint/timing/transport causality unresolved; the passing native
control is not used to declare a confirmed production source bug. The inline
control again never reaches a usable session and its owner is withheld. No
zombie, failed callback or incomplete example is whitelisted as a pass.

The root focused helper suite passes **42/0** (35 focused and seven support
examples). Changed Ruby lint, module-documentation tidy and acceptance dry runs
pass. The full local RSpec suite is not run. The human Scenarios body retains the
3,600-byte digest above. Other releases, nginx/Apache, MySQL, TLS, custom prefixes,
Linux fetch/default selection, other cipher families and payloads remain outside
qualified coverage.

## Self-review

**Summary:** Native fixtures qualify exact command and real shell paths while
retaining the three distinct failures without increasing their qualified counts.

**What looks good:** Independent genuine Laravel controls precede owner command
verdicts; real session APIs, physical proofs, process births, database rows and
exact Docker-object removal provide separate oracles. The shared crypto repair
has an identical before/after regression suite and a one-input native replay.

**Concerns:** The application-specific cookie name is a confirmed owner defect.
The default staged and inline PHP Meterpreter paths remain unresolved and
unqualified. A passing native CLI control does not settle the default owner's
different delivery context.

**Suggestions:** Investigate cookie discovery separately and preserve the
failing case. Continue the PHP entrypoint/framing investigation using exact
generated bytes before changing the payload runtime or claiming default-session
compatibility. The Invoice Ninja counterpart is the next shared-helper candidate.

The final maintained capsule is `invoiceshelf-maintained-20261120T193333`: **311 files**, manifest SHA-256
`3f61220528708edbd1905be97d773c5db99e99cccdfd5cf2365bb7cb1a6e8819`. Its frozen inputs and raw results remain separate
from the earlier failed/interrupted capsules.
