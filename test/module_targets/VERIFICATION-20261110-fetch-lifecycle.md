# Fetch service ownership requalification

The shared repair is qualified by native component controls and all **42**
affected Solr/OpenWire functional cases. This preserves the existing **132
runtime modules, 65 families and 892 cases** from the
[OpenWire checkpoint](VERIFICATION-20261110-activemq.md), with current recorded
inputs and a stricter cleanup contract. No new module is counted for a library
repair. The broader campaign remains active; no PR or full local RSpec run.

## Reproduced ownership defects

`cleanup_http_fetch_service` removed its resources but assigned nil only to a
local variable. It never released the caller's service reference. Native controls
observe actual HTTP/HTTPS listeners, service aliases, reference counts, Linux
LISTEN inodes and file descriptors remaining after cleanup. Repeated acquisition
grows refs from 2 to 3 and beyond. A retired adapter also retains its route names:
after another owner takes the same URI, its failed retry cleanup can remove that
new owner's live resource.

The common helper now clears only its caller's ownership list and releases
exactly that caller reference through the existing `deref`. The nil return and
HTTP/HTTPS adapter pointer guards remain. ServiceManager, sockets, threads,
payload launchers, dependencies and shared timeouts are unchanged. A concurrent
owner retains its actual 200 response; removed routes return 404 while that
owner remains. Final-owner cleanup removes aliases, descriptors and listeners,
and real connections refuse. No global stop or manual release is needed.

The original native checkpoint has nine scenarios, fifty-five snapshots and
eighty-three HTTP(S) probes. The identical repaired script records forty-two
snapshots and sixty probes: twenty-eight exact 200s, eight other-owner 404s and
twenty-four real refusals. Each final service has zero refs/aliases/LISTEN FDs.
The different counts reflect actual retained-service operations, not omitted
scenarios. Original native controls separately resolve an apparent Darwin timed
Socket return as an unconnected socket after refusal; no Ruby/socket workaround
is introduced or listener closure inferred from that returned object.

## Focused tests and complete consumer replays

| Verification | Before | After | Scope |
| --- | --- | --- | --- |
| Worker host focused | 62/12 | 62/2 | Ten new lifecycle regressions; two inherited Mach-O/ELF failures |
| Worker host applicable | — | 60/0 | Both unchanged generated commands separately pass on Linux |
| Parent canonical Linux focused | 62/10 | 62/0 | Same four files and real HTTP/HTTPS; both ELF cases pass |
| Parent host default mode | — | 69/2 | Same 62 plus seven shared formatter examples |

The parent Linux pair uses the same cached canonical image, source mounted read
only and network none. The original helper is overlaid as one read-only file
for the before run. No build/install is needed. Before/after RSpec durations are
4.934447819/4.799969806 seconds, with zero pending/outside errors. Source maps
differ only in the helper; per-run ports/configs/seeds naturally differ. An
earlier pair has zero examples/one outside setup error because default
spec_helper requires a configured database. Those are retained separately; the
proper standalone mode explicitly loads msfenv/msf/base and its own config.

| Final consumer profile | Invocation | Cases/failures | RSpec seconds | Inputs |
| --- | --- | --- | --- | --- |
| `solr_velocity` | `20261110T005727-4874e1` | 10/0 | 201.338972 | 54 |
| `solr_velocity_sessions` | same | 6/0 | 296.669013 | 56 |
| `solr_backup` | same | 12/0 | 273.770835 | 69 |
| `activemq_openwire` | `20261110T012157-81f1a4` | 14/0 | 382.184 | 55 |

Solr retains sixteen used sessions, eight empty-registry checkpoints, four actual
former-URL `Errno::ECONNREFUSED` responses and six exact FETCH_DELETE absence
receipts. Every callback/stager/Fetch LISTEN port is absent. OpenWire retains
eight used sessions, real Linux curl refusals at every former route/port and an
empty service registry. Its observer copies owned paths before cleanup clears
the list, with all serialization/file I/O after production cleanup.

The first strict OpenWire55 run is **14/2**, not a qualified pass. Its two
downloaded files are observed too early because `wait_for_expect(10, 0.1)`
counts attempts, not seconds. Both actual launchers use sleep7; both files later
disappear in native receipts without operator deletion. The corrected spec uses
an actual ten-second wall-clock bound and returns immediately on exact directory
restoration. All eighteen final receipts pass, longest 4.835287 seconds. Only
spec/guide values differ between those two 55-key runs; module/helper bytes are
unchanged. This is a fixture timing correction, not a launcher repair.

## Retained integrity and limits

The parent byte-verifies **378** files from the complete final Solr invocation
and **60** from OpenWire, including hidden metadata. All 54/56/69/55 profile
inputs match current files. The parent audits the final three Solr projects and
fourteen volumes plus OpenWire project absent. Worker cumulative OpenWire audit
covers nineteen containers/six networks, no volumes. No unrelated resources stop.

| Immutable export | Independently verified entries | Manifest SHA256 |
| --- | --- | --- |
| `fetch-http-lifecycle-original-20261110-b4e90307c4b` | 125 | `6b3326d482c1a4d64f5c0ac6257f029a7333fa545e56c1d398462860626528ae` |
| `fetch-http-lifecycle-linux-parent-20261110-078e980e639` | 116 | `b14b44824b89d6f86ae29d8175f3af9cae350d565401a2f30c7702cd186b40d6` |
| `fetch-http-lifecycle-validation-20261110-2b70afd4290d` | 948 | `a55a0611ebc043d58a99154924a15487735f8552ddd038b0dbf898b3815fcf8b` |
| `activemq-openwire-fetch-20261110-81e526f28e2` | 322 | `4ed52b948e081098a3019b98a4888f1a2751d5d34b5a07eb0d6e5708df5b7930` |

These exports preserve every earlier passing/failing qualification and source
snapshot. The combined Fetch seal truthfully recorded its then-pending OpenWire
hold; it remains unchanged and the later acceptance is recorded here. New
lifecycle specs and consuming Ruby lint clean; the common helper retains nine
existing lint findings versus ten originally (the missing final-newline finding
is removed). Earlier module/doc findings remain as recorded in the Solr/OpenWire
reports. Human Scenarios remain unchanged.

Declared hashes are not the whole dependency graph. HTTP/HTTPS ownership is
covered at component level; functional consumer scope remains the actual Linux
targets/delivery families recorded above. This does not qualify every composed
Fetch adapter/platform/transport or resolve unrelated WordPress/Ansible issues.
