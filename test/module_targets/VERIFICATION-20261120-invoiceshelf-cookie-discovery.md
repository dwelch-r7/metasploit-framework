# InvoiceShelf cookie discovery follow-up

This follow-up repairs the genuine renamed-cookie failure retained in the
[original investigation](VERIFICATION-20261120-invoiceshelf.md). The final replay
qualifies **20/0 across seven profiles**, with six real shell sessions used and
closed. The newly qualified named/custom/domain profiles add six historical
cases, reaching **315 runtime owners in covered paths, 662 qualified profiles
and 4,745 historical functional cases**. Repeated cases add no campaign counts.
Default and inline PHP Meterpreter profiles remain unqualified.

## Source repair

The owner now authenticates the returned data cookies and finds the encrypted
session pointer whose value names the matching data-cookie ID. It supports the
normal name, `APP_NAME=InvoiceShelf`, a genuine
`SESSION_COOKIE=module-target-cookie`, and more than one returned forty-character
cookie. Malformed candidates and unrelated authenticated cookies do not select
a false pair. Each execution uses the current response without changing operator
options or retaining a previous chain. Existing APP_KEY and BRUTEFORCE options
remain available.

Framework's existing cookie scanner provides the parsing. The small additive
`HttpCookieJar#parse_response` API returns response cookies without adding them
to the jar or applying browser-domain acceptance. Existing parsing/storage APIs
retain their behavior. This distinction matters for forged requests made to an
IP address when the application declares another cookie domain.

The redundant forced PHP payload is removed; a real normal Framework chooser
selects `php/meterpreter/reverse_tcp` before and after, with target 0 and port 90
unchanged. The generic Unix target retains its established Bash default with a
narrow explained lint exception: automatic selection prefers a Linux-only fetch
payload. This source repair does not modify the payload runtime or delivery code.

## Independent regression evidence

The unchanged renamed-cookie native profile changes from **2/1 to 2/0**. Its
only changed original runtime input is the owner module. Both repeated owner
commands reproduce the native file bytes as UID 33 and remove their artifacts.
Its 64-file capsule is `invoiceshelf-named-cookie-fixed-replay-20261120T201028`,
manifest `f9be0a9c865d14a8a45c930b4313a7d554ae3223a35cfdc7b5e107fc826da2c7`.

An initial unit suite used genuine HTTP headers and independently decrypted IDs
captured from the original 1.3.0 backend. HTTP and command payloads are explicitly
doubled; cookie parsing, HMAC and AES are real. The final owner suite has sixteen
focused examples plus seven support cases: **23/0**, versus seven failures on the
original source. It covers named/custom cookies, response order, unrelated valid
and malformed candidates, wrong references, missing cookies/data, wrong keys,
key-file selection and a second response on the same module instance.

A three-case library suite verifies raw value/domain preservation, missing-header
return shape and absence of jar mutation: **10/0** raw, including seven support
cases. The existing cookie-jar suite passes **41/0** raw, with 34 original class
cases and seven support cases. No full local RSpec suite is run.

## Review caught a browser-storage regression

The first candidate used the ordinary keep-cookies storage path. It passed the
named-cookie replay and an 18-case valid-domain matrix, but a new IP/domain unit
case failed: browser acceptance discarded an otherwise usable server cookie.
The native domain fixture confirms that regression. With
`SESSION_DOMAIN=localhost` and HTTP sent to the published IP address, the genuine
Laravel control executes and removes its proof, then the candidate owner aborts
because its jar is empty. The profile records **2/1**. The native parser uses the
declared cookie origin solely for parsing; its HTTP request still reaches the
real lab endpoint. No backend response or vulnerability is mocked.

The final response-parser API changes that same fixture to **2/0**, including
repeat execution. Only the owner and shared jar library differ among its declared
runtime inputs. The unsuccessful 65-file capsule is
`invoiceshelf-domain-candidate-regression-20261120T203457`, manifest
`bdf98ffffa49de9c4faa5ce18a4c791cd1603ec8bef398d49996224f49abb3b6`.
The corrected 66-file capsule is
`invoiceshelf-domain-fixed-replay-20261120T203918`, manifest
`15d30d11caf0ce1f855e127899e29b199a4b20cce580435cfe6ccdb3e132a075`.
The earlier 303-file candidate matrix is retained as
`invoiceshelf-browser-jar-candidate-20261120T201613`, manifest
`83900db38374dfcb5886311651eceb6913769cef5fd5877a60919b1ab35c17ab`.
None of those intermediate runs increases campaign totals.

The final 66-file source capsule is
`invoiceshelf-unfiltered-cookie-source-20261120`, manifest
`fca55318fd01dc447ea29b881b20eaecd824bc04f4891d11767b10cf2f57829f`.
The source was developed separately on `invoiceshelf-cookie-discovery`, then
integrated as `35f90ef2488` and `f611edebb47` before native qualification.

## Final native replay

| Profile | Actual examples/failures/pending | Verdict |
| --- | --- | --- |
| `invoiceshelf` | 8/0/0 | Qualified command/key paths |
| `invoiceshelf_file_sessions` | 2/0/0 | Qualified mitigation |
| `invoiceshelf_named_cookie` | 2/0/0 | Qualified renamed pointer |
| `invoiceshelf_custom_cookie` | 2/0/0 | Qualified arbitrary pointer name |
| `invoiceshelf_cookie_domain` | 2/0/0 | Qualified mismatched cookie domain |
| `invoiceshelf_bash` | 2/0/0 | Qualified first/repeated Bash sessions |
| `invoiceshelf_php_shell` | 2/0/0 | Qualified first/repeated PHP shells |
| `invoiceshelf_php_staged` | 2/1/1 | Native readiness failed; owner withheld |
| `invoiceshelf_php_inline` | 1/1/0 | Native readiness failed; dependent case not reached |

The complete invocation deliberately exits nonzero: **23 examples, two failures,
one pending**, with no errors outside examples. Native Meterpreter failures are
not counted as confirmed owner failures. The earlier successful native staged
session followed by a failed default owner attempt remains in the original
investigation; this phase does not overwrite that history or identify its cause.

Both shell families use an independent handler and two owner sessions. Physical
file bytes, UID 33, PID/birth/socket state, public session APIs, payload metadata
and closure of each original reporting row verify all six lifecycles. Repeat
execution preserves the selected console object with AutoCheck disabled.

The final 337-file capsule is
`invoiceshelf-unfiltered-cookie-final-20261120T204113`, manifest
`36a6f122a874172559dd5316f0b152c73b5a8a8fbb1601d2f92d8611b3421335`.
Its independent audit verifies all **60 recorded input files unchanged**, all
**26 resource-event captures zero**, and absence of all **22 exact Docker
objects** after cleanup. No more than two capped containers run at once. The
global running/stopped container inventory is empty after the investigation.

## Verification scope

Owner/spec Ruby lint and module tidy pass. Four lint offenses in the existing jar
library match its original cop/source lines exactly; no new library offense is
introduced. Positional cleanup and existing iteration code remain unchanged.
The regression analysis does not turn the new API's missing-method failures on
old source into production bug claims.

The test app, pinned 1.3.0 release, thirteen vendor/application source checks,
SQLite installation and PHP test-server scope are the same as the original
fixture. No vendor patch or private Meterpreter experiment is installed. All
stacks are namespaced, capped and serialized, with cleanup and independent exact
resource inspection. The historical human Scenarios body is preserved.
Other releases, MySQL, TLS, alternate cipher families, nginx/Apache, redirected
login paths and other public payload families remain outside this qualification.

## Self-review

**Summary:** The cookie repair and maintained native profiles qualify the seven
paths above; the broader campaign remains active and no PR is created.

**What looks good:** Real application controls precede owner verdicts; response
parsing preserves cookie bytes without jar mutation or browser-domain rejection.
The 53 focused owner/new-library/legacy cases pass (74 raw examples across three
invocations, including repeated support cases).

**Concerns:** Stock staged and inline Meterpreter remain unqualified, with their
original failures and current native-readiness failures retained separately.
Four inherited jar lint offenses remain; no new offense is introduced.

**Suggestions:** Investigate native Meterpreter readiness and the earlier default
owner failure separately before extending PHP session qualification.
