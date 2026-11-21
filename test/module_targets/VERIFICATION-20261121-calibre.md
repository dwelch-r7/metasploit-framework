# Calibre native execution and shared transport repairs

Five freshly executed profiles pass **24/0**, with **seven real sessions used
and closed**. The new Calibre profile passes **8/0**, adding one runtime owner,
one qualified profile and eight historical cases. Campaign totals reach
**319 runtime owners, 675 qualified profiles and 4,799 historical functional
cases**. Older profiles retain their historical results; this report does not
requalify them against the changed shared HTTP and test-console sources.
The broader module-inventory goal remains active. No PR is created.

## Genuine target and native prerequisites

The [Calibre recipe](calibre/README.md) installs the official Linux amd64
**7.14.0** binary on pinned Ubuntu 22.04. The downloaded archive is 146,597,996
bytes with SHA256
`b9a53fbbbe6294ba1eb0ba699f8431249a241e0098b0b62a8fb6940e0b99e810`.
The Docker build checks the vendor-published SHA512 recorded in Compose. The
checksum was retrieved with certificate and hostname verification using the
CA embedded in the official HTTPS installer; TLS verification was not disabled.

The actual application runs headlessly as **UID 1000**, with bundled Python
**3.11.5**. Normal `calibredb` startup creates a genuine library and one book,
ID 1, titled `Module target calibration`. The unauthenticated content server
does not enable write access. No installed vendor source, payload runtime or
HTTP transport is patched.

The seeded book is a functional prerequisite: this list endpoint evaluates the
template for matching books. An empty library would not prove remote execution.
Before and after the run, the real version, Python version, UID, book identity
and four installed function fingerprints must match
[the committed capture](calibre/installed-7.14.0.json). The functions cover the
list implementation, HTTP dispatch and both template formatter entry points.

Independent controls use the installed Python standard-library JSON encoder
and `repr` to build their RPC envelope and command literal. Generation must
leave the physical proof absent. Local genuine `SafeFormat` evaluation and the
real `/cdb/cmd/list` HTTP endpoint must then separately create the exact expected
bytes as UID 1000. Each proof is removed and its absence checked before reuse.
These gates establish native capability before invoking the Framework owner.

The corrected native-only pilot passes four byte families with **eight physical
local/HTTP proofs**. The maintained Calibre profile runs thirteen controls,
yielding **26 native physical positives**, followed by twelve actual owner
commands with exact physical bytes: **38 positive file observations** in total.
No module success message substitutes for that evidence.

## Retained failures and confirmed repairs

| Retained phase | Actual result | Classification |
| --- | --- | --- |
| First image startup | Missing `libGLX.so.0`; owner not invoked | Setup dependency failure |
| Original Calibre owner | 8 examples, 4 failures | JSON/Python command serialization defects |
| JSON/Python repair alone | 8 examples, 2 failures | Shared HTTP character-count defect |
| First five-profile replay | 24 examples, 1 failure | Test-console asynchronous output race |
| Final five-profile replay | 24 examples, 0 failures | Qualified stated coverage |

Installing the normal `libglx0` system package resolves the first startup
failure. Native execution, all installed function pins and final health then
pass. The failed setup is retained separately and supplies no module verdict.

The original owner manually interpolates commands through a Python
single-quoted literal and a hand-built JSON envelope. Native-proven single
quotes reach valid JSON but invalid Python; the real server returns HTTP 200
with `TEMPLATE ERROR` and creates no proof. Double quotes, literal LF and the
combined quoting case produce invalid JSON and HTTP 400. ASCII and Unicode
commands succeed and repeat. The module's HTTP-200 success message alone would
therefore misclassify the single-quote case.

The module repair encodes the command as a JSON string literal usable by Python,
assigns it once in the template and separately JSON-encodes the complete RPC
array. It preserves command bytes and the caller's string encoding, existing
Windows-to-shell fallback, targets, options, defaults and response handling.
Seven focused source examples plus seven automatically loaded support examples
change **14/3 to 14/0** on identical final spec/fixture inputs. Actual HTTP tests
and Python AST inspection establish template semantics beyond the unit suite's
JSON envelope checks. An early namespaced `Encoding` constant mistake is also
retained; it was corrected to `::Encoding` before the repaired runtime attempt.

After that source repair, quoted and multiline cases work, but Unicode and the
combined case still fail against genuine HTTP. Captured JSON and Python syntax
are valid. The request body is **332 octets but 327 Unicode characters**. Rex's
request builder advertises the character count, so the server receives a
truncated JSON document and returns HTTP 400. The fix changes automatic length
calculation to `bytesize` in `ClientRequest` and `Packet`, at their real HTTP
serialization boundaries. No binary-body workaround is added to the module.

Ten deterministic HTTP regressions cover the real captured request,
headers-only serialization, complete body/caller encoding, response round-trip,
binary data, gzip and preserved explicit header overrides. The same five-file
HTTP suite changes **118 examples / 4 failures / 8 pending** to
**118 / 0 / 8**: **110 passing examples and eight unchanged pre-existing pending
examples**, rather than 118 passes. A preliminary gzip assertion mistake is
retained separately and corrected before the source comparison.

The first combined replay passes the four command/check/discovery profiles,
then fails on Perl's repeated session invocation. A real asynchronous
`Command shell session ... opened` message arrives after a complete JSON result
but before `puts` emits its newline. The old greedy line matcher includes that
status text and raises `JSON::ParserError`. This is a harness failure, not
evidence of a broken Laravel module or target.

The shared test helper now writes Base64 JSON between fresh per-request
delimiters and extracts that bounded frame without requiring a clean line
boundary. Stateful expressions are evaluated once. Six focused tests execute
the actual Ruby producer and cover clean results, the captured trailing status,
status on both sides, Unicode/control/marker data, false values and single
evaluation. With seven support examples, the suite changes **13/2 to 13/0**.
The fixture records the TEST-NET substitution applied to captured endpoints.

That failed session frame had **four sessions actually used and closed**:
the native handler and the first invocation's three owner sessions. The repeat
opened three callbacks but its proof was withheld by the JSON failure; they
are not counted as used. Cleanup closes all six original owner reporting rows
across both invocations, restores the full process baseline and removes every
socket. All raw evidence and the harness failure remain retained.

## Actual current owner results

| Fresh profile | Examples/failures/pending | Used and closed sessions |
| --- | --- | --- |
| `calibre` | 8/0/0 | 0 |
| `laravel_token` | 9/0/0 | 0 |
| `laravel_token_fixed` | 3/0/0 | 0 |
| `laravel_token_env` | 2/0/0 | 0 |
| `laravel_token_perl` | 2/0/0 | 7 |

Calibre's real check returns reason-bearing **Appears** for 7.14.0. The Linux
command target is explicitly selected with `TARGET 1` and `cmd/unix/generic`.
Six command families cover ASCII, single quotes, double quotes, Unicode,
literal LF and combined CRLF/quotes/metacharacters. Each runs twice on the
same selected console object, with AutoCheck enabled first and disabled for
the repeat. Actual encoded commands, request/response artifacts and source
trace events are retained. All twelve commands create exact UID-1000 bytes;
proof removal, final health and all four installed pins pass.

All four Laravel companions are replayed after the shared helper repair.
The vulnerable command profile retains native-positive and wrong-key controls,
both check gadgets, debug-page discovery and thirty actual command executions
across ten positive observations. The `.env` profile independently verifies
that discovery path and six owner executions. The genuine fixed 5.6.30 profile
proves nine local positives before denial of the identical encrypted tokens by
HTTP, then verifies four check POST denials and eight repeated owner denials.

Perl independently calibrates its normal handler, then exercises default and
explicit repeat selection on one console object. Both owner invocations create
three callbacks. Every actual session, including the native handler, proves
physical UID-33 execution, persistent PID/birth, an open socket and its original
reporting row. Public EOF closure removes all seven processes/sockets, closes
every original row and restores the complete baseline. The legacy owner
fallback loop still emits duplicate callbacks; this change does not repair it.

## Inputs, checks and cleanup

Independent audits reconcile **67 current declared inputs** across these five
profiles. The outer wrapper freezes 68 inputs, including runtime/dependency
and wrapper controls; the runner additionally registers five Framework/support
files. Both sets match their captured hashes. Each current manifest explicitly
declares the two changed Rex HTTP sources. No private runtime override is used.
Stage-specific input deltas separate the module repair, added HTTP dependencies
and later shared-console change; they do not claim an owner-only final delta.

The five profiles have **24 zero memory/PID event captures**. Stacks run
serially, peaking at **two capped containers**. Calibre uses 1 CPU, 768 MiB
memory/equal swap and 128 PIDs; Laravel applications use 1 CPU, 512 MiB and
128 PIDs. Perl's reporting database uses 0.2 CPU, 128 MiB and 64 PIDs. Published
ports bind only to loopback. Ensure cleanup runs after success and failure.

All **thirty new Docker objects** from both native pilots and four functional
frames are independently absent. Rechecking the prior 325 verifies **355 absent
recorded objects**. The final global inventory includes stopped containers and
is empty; no owned ephemeral network or volume remains. No new agent/tool helper
container was started. The user's broader cleanup instruction was applied to
the global inventory, which was already empty at that check.

The four new Calibre Ruby helpers/specs and two console Ruby files pass
RuboCop. The existing Calibre module retains the same three offenses, with
msftidy exiting 2 for those inherited offenses. The four existing HTTP
source/spec files retain 490 identical inherited offenses. Neither set gains
new offenses. Module-document tidy exits 0; its original human Scenarios remain
1,860 bytes with SHA256
`22d1711b18e4bc9715f81c1add515d2a61c2832300006274a326cb6c06e4b8f2`.
Automated captures are not substituted for human Scenarios.

## Evidence and limits

Immutable local capsules under `/Users/dwelch/.codex/reports/` contain frozen
inputs, native and owner output, source comparisons, audits and exact cleanup
receipts. The maintained capsule links every preceding failure/fix capsule.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `calibre-native-missing-glx-20261121t031259` | 37 | `a0636ab0acff3b9415bae6f8a95536902b920c11c2aec4b794fa982478eccb7f` |
| `calibre-native-ready-20261121t031412` | 129 | `737cbd0ddb0fbf15c0106011bb1ec866997b3d64e80f7018690b64289a4a20b1` |
| `calibre-original-owner-20261121T031911` | 92 | `a2549aa458e7022fcee8440c490b927cd5b90cac56fa970ae68e816ee769ed5d` |
| `calibre-command-serialization-source-fix-df28594a860b` | 42 | `23edee3166086ad701786021fd416387f236d465357ccf5193b7168c4c763142` |
| `calibre-json-unicode-transport-failure-20261121T032853` | 96 | `ae37706a3083397ce415656b7513d0e2bd707372d590f8bda15f20bbb17cc0c3` |
| `http-content-length-byte-fix-4c06b3748e8f` | 29 | `a5e22cd79e15772340aedd1d11a27e0dbdc2c47c5adb9a9492cdaf75f2304c9e` |
| `calibre-and-laravel-console-interleave-20261121T034712` | 417 | `782ce74b445e1cec1a30c7e92ef7eaa96de5b8d2e55b669846d86f3fba6fdddc` |
| `module-console-json-framing-source-fix-2b4e97619d82` | 16 | `a16c3bcb249a1754aac9d5d108099c66b2708471773578fb55ec331e2d3186f3` |
| `calibre-and-laravel-maintained-20261121T041213` | 448 | `98ab96b369a37ec88b252aee6ad9bd6b8b9b9831c5fe5c46c5328031460cc737` |

Calibre Windows/global-default target 0, Linux's default Python Meterpreter,
other payload families and releases, the 6.9 minimum boundary and genuine
7.16.0 fixed-release runtime are **unqualified**. Official 7.14/7.15/7.16 source
inspection informs future boundary testing but supplies no runtime result for
untested releases. Empty-library behavior and better confirmation of HTTP-200
template errors remain follow-ups. Raw backslash commands excluded by existing
owner metadata are outside this profile. Earlier native PHP Meterpreter and
Ignition log-state failures also remain retained for investigation.

## Self-review

**Summary:** A genuine native-gated Calibre target exposes and verifies fixes
for command serialization and shared HTTP framing, with a separate console
harness repair and all five stated profiles replayed.

**What looks good:** Native proofs, exact request/body evidence, same-input
source regressions and physical owner repeats distinguish setup, module,
transport and harness failures. All sessions close and all containers disappear.

**Concerns:** Shared code changes do not requalify the older historical matrix.
Default Calibre sessions, other platforms/releases and the retained failures
above still need independent qualification. Inherited lint/pending limits remain.

**Suggestions:** Calibrate Calibre's default Linux session path and genuine
fixed-release controls, investigate empty-library success reporting separately,
then continue the remaining valuable container-feasible inventory.
