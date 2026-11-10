# ActiveMQ OpenWire execution qualification

The selected checkpoint covers **132 runtime modules, 65 families and 892
functional cases**, adding one module and fourteen cases to the
[Prometheus checkpoint](VERIFICATION-20261110-prometheus.md). Selected results
have exact counts, zero failures/pending/outside errors, current recorded input
hashes and owned teardown. The broader goal remains active. No PR was created
or full local RSpec suite run.

## Genuine brokers and native controls

The [OpenWire lab](activemq_openwire/README.md) builds genuine Apache 5.18.2
and fixed 5.18.3 from publisher-SHA512-verified archives. A digest-pinned official
Temurin 17 image reports Java 17.0.21. Vendor OpenWire decoding and independent
authenticated, Origin-aware Jolokia queries agree on actual broker versions.
The native gate performs thirty-eight operations, including real JMS delivery
and destination removal before/after repeated command execution attempts.

An independently encoded ExceptionResponse reaches the actual broker. Its
Spring/ProcessBuilder execution must create a file owned by `activemq`, whose
recorded parent PID equals the real broker JVM. The fixed broker fetches no XML
and creates no proof. A native HTTP listener serves static XML bytes only.
It never executes the command or substitutes for a broker. Logical JMS and
temporary-file state is restored after both repetitions.

| Retained invocation | Cases/failures | RSpec seconds | Classification |
| --- | --- | --- | --- |
| `20261110T000023-1b3946` | 14/10 | 196.803894 | Mixed payload-selection, lifecycle-assertion and command symptoms |
| `20261110T001854-52f881` | 14/1 | 381.985529 | Corrected fixture, original module; native gate passes |
| `20261110T002903-6a26cf` | 14/0 | 418.656825 | Matched repaired module; 49 current inputs and owned teardown |

The first attempt includes six incompatible payload choices rejected before
module execution and two successful Meterpreter deliveries followed by an
incorrect physical-listener assertion. It is not ten demonstrated module defects.
Corrected fixtures retain genuine Linux fetch payloads and Unix commands, plus
an observation of actual resource ownership. The matched final pair differs in
only the owning module; all 49 keys and other bytes remain identical.

## Callback repair and strict outcomes

The corrected original fails only the explicit Unix disabled-payload-handler
case. It returns before the actual XML callback and removes the resource;
the expected delivery trace and independent command file are absent. The same
commands execute through native and ordinary-handler paths. Stock vendor INFO
logs do not show the failed broker HTTP attempt, so separate cleanup 404 probes
are not described as a captured broker 404.

The owning repair resets acknowledgment per exploit, acknowledges only after
sending the matching XML response and waits for that acknowledgment when the
payload handler is disabled. Enabled session waiting and ensured cleanup remain.
Unrelated paths return to the parent without serving or acknowledging command
XML. Existing bounded Retry/WfsDelay semantics are unchanged.

Final cases cover both versions, AutoCheck refusals, Linux fetch-exec and Unix
commands, root/prefix callbacks, XML-sensitive text, AutoCheck-disabled setup,
disabled handlers and invalid CDATA. Four command shells and four Meterpreter
sessions are opened and used. Ten command proofs and eight session proofs verify
actual file ownership and exact temporary-file restoration across repeats.
No positive result permits an operator abort or runtime exception.

The acceptance-only observer retains existing object/path references, calls
production cleanup immediately, then performs all serialization and file I/O.
It does not wrap or delay the XML callback. Every owned route must disappear.
Real Linux curl probes require HTTP 404 for empty listeners actually owned by
Fetch; never-Fetch listeners must refuse connections. This checkpoint records
the old shared Fetch reference leak explicitly. It does not claim pooled
listener closure; the separate repair and stricter Solr/ActiveMQ replays are
still under qualification.

## Verification and integrity

Focused tests improve **27/3 to 27/0**: twenty owning examples and seven shared
formatting examples. The parent repeats all twenty-seven, with no pending or
outside errors. Two actual native greetings are distinguished from twelve
derived advisory boundaries. Five changed Ruby files lint clean; module tidy
passes. Module docs retain two inherited messages and preserve human Scenarios.

The parent imports and byte-verifies all **59** regular files, including hidden
files, of the final invocation and checks all 49 inputs against current source.
It independently audits the final project absent. The worker audits thirteen
containers and four networks across the OpenWire native/Framework attempts;
none has a volume. Later Jolokia preparation is separate and does not qualify
another module here.

The durable `activemq-openwire-20261110-43c81c3a1b4` export retains all original
attempts, source/input freezes, native/vendor controls, independent proof and
state logs, and separate source/lab commits. The parent independently rereads
all **546** manifest entries; `manifest.sha256.json` digest:
`3c2712de8f913b7160e0e206b43a43d3ab5cb21f6d0a6d28f344b246951dcf53`.
Large vendor archives remain in the active worker; exact publisher provenance
and uniquely named authoritative source extracts are retained in the export.

Aggregate selection is `tmp/module-target-checkpoint-activemq-old-fetch.json`.
Declared hashes are not the full dependency graph. Windows, TLS, other CPU
architectures, fetch commands and ActiveMQ branches remain unqualified.
Jolokia, capture protocols and Docker Engine are separate ongoing profiles.

## Existing CI fixture follow-up

The previously failing Verify example stubs an OpenSSL extension to display
`ms-ntds-sec-ext` even where the native registry cannot resolve that name.
Independent OpenSSL 3.0.15 controls accept the numeric OID and reject that alias;
3.5.9 displays and resolves the alias natively. A separate five-line spec repair
models the corresponding resolver entry within that example. Production
certificate code and the global registry remain unchanged.

The complete focused file passes **46/0** before/after on local OpenSSL 3.5,
then **46/0** in the parent. Two identical inherited lint categories remain.
This is not a local full-Framework run on OpenSSL 3.0 or proof of green CI.
The checksum-verified `icpr-openssl-fixture-20261110-2f3f3420900` export retains
native boundaries, original Verify16,971/1/664 and rerun8/1 logs, and all focused
results: 22 checksum entries, manifest digest
`eb454ecbd4a32c8ab81d40d16680c2719ae15fccce3abec9b1b1254f0c0715a8`.
