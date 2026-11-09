# RabbitMQ discovery, authentication and Erlang execution

The selected checkpoint covers **125 runtime modules, 59 families and 809
functional cases**, adding three modules and twenty-nine cases to the
[Kubernetes checkpoint](VERIFICATION-20261109-kubernetes.md). Every selected
profile has exact counts, zero failures/pending/outside errors, current recorded
input hashes and owned teardown. The broader goal remains active. No PR was
created or full local RSpec suite run.

## Genuine targets and results

The [RabbitMQ lab](rabbitmq/README.md) pins official Linux amd64 RabbitMQ 3.8.16
and 3.12.14, actually running OTP 24/ERTS 12.0.2 and OTP 25.3.2.15/ERTS 13.2.2.11.
Vendor CLI/RPC, native connection frames and independent Pika TCP/TLS clients
establish identities, users, permissions, verified TLS 1.2 and genuine
publish/get messages. A disposable PostgreSQL verifies credential persistence
with direct SQL and rejects a wrong database password.

Seventeen strict AMQP cases cover version/cluster/platform/mechanisms, service
records, repeated credentials without duplicates, bad passwords, loopback-only
guest, limited accounts and workspace isolation. SQL checks exact credentials,
origin, private type, service, status, timestamp and workspace links. The scanner
authenticates through connection.tune; native Pika separately demonstrates that
a valid limited account cannot open `/` but can exchange messages in its allowed
vhost. Scanner success is not a claim of queue/vhost authorization. Both AMQP
modules and shared AMQP code remain unchanged.

The [Erlang profile](erlang_cookie/README.md) adds twelve cases: repeated short,
255-byte and 256-byte commands, rejected cookies, genuine Bash command shells
and Linux x64 Meterpreter staging on both brokers. Eight fresh sessions must
execute native file/identity proofs; every repeat restores exact target state.
All twenty-one positive examples reject operator failure banners. Eight
negative examples retain explicitly expected refusals.

| Canonical evidence | Cases/failures | RSpec seconds |
| --- | --- | --- |
| `20261109T212146-9751c1`, original AMQP | 17/0 | 115.419913 |
| `20261109T212712-89a54a`, mixed Erlang/harness | 12/12 | 143.078593 |
| `20261109T213303-dc8a18`, corrected original Erlang | 12/9 | 148.017774 |
| `20261109T214318-d2c807`, bounded original state observer | 12/9 | 206.457321 |
| `20261109T215437-105d58`, framing/auth repair | 12/1 | 213.339976 |
| `20261109T224630-016ec4`, completion repair | 12/2 | 185.891667 |
| `20261109T225433-1b2d29`, lifecycle repair/strict positives | 12/0 | 193.515107 |
| `20261109T231353-6b32d8/rabbitmq`, final health-fixed | 17/0 | 127.110006 |
| `20261109T231353-6b32d8/erlang_cookie`, final health-fixed | 12/0 | 146.182855 |

Every terminal RSpec suite has zero pending/outside errors, passing native
controls and passing teardown. Final profiles each pass fifty-six native
operations; Erlang additionally requires four real background/completion/cleanup
programs. The parent imports and byte-verifies all **127** regular files of
the final combined invocation and independently verifies both 43/46 input sets.

## Classified failures and owning repairs

Eight initial Erlang failures stop before module execution at Ruby positional
Hash/keyword ambiguity in the harness. Correcting those calls exposes real
framing/authentication defects and persistent stager artifacts. A bounded
ten-second exact-state observer confirms persistence independently of immediate
cleanup timing. These runs remain distinct.

The first owning repair fixes fixed-width frame/node/command lengths, complete
bounded legacy/modern handshakes, required capabilities/complement, authenticated
acknowledgments and ensured disconnect. Native vendor term decoders reject
original emission and accept repaired bytes; actual broker captures distinguish
OTP 24 acceptance, OTP 25 capability refusal and wrong-cookie closure. Offline
method emission/decoding is explicitly distinguished from native wire captures.

The remaining artifact failure is independently explained by concurrent legacy
rex workers. A derived one-second delayed-write stress control demonstrates
cleanup overtaking a write; consuming actual matching replies restores ordering.
It is not claimed as observed payload latency. Linux staging now separates
commands, backgrounds launch through existing stager options, retains the
ordinary 250-millisecond delay and waits for the actual sender PID and rex result.
A small reusable bounded typed ETF decoder handles the observed term forms;
ticks, unrelated messages, malformed/unsupported and over-budget terms cannot
release staging. Ordinary reverse commands stay nonblocking; Windows staging
behavior remains unchanged and unqualified.

Two subsequent Meterpreter paths lose their final cleanup RPC connection.
Source and real socket-abort regressions establish that session registration
closes tracked sockets. The narrow Linux stager branch preserves only its
authenticated distribution socket until ensured disconnect; other tracked
sockets retain their normal abort behavior. The final suite proves eight
sessions with restored state and strict positive output.

Focused comparisons are **34/19 → 34/0** for framing/authentication,
**53/16** before completion against the already repaired source
`83934887ce3225f7a270a99501a3fe00eb3f59ce76c4b80614d357e0dcac485c`,
and **95/1 → 95/0** for session lifecycle. Final **96/0**, repeated by the parent,
contains 48 module examples, 41 decoder examples and seven shared examples.
Actual captures and derived boundary/delivery patterns are labeled separately.
Seven new library/spec/native files lint clean; production retains eleven
inherited offenses, down from twenty-five, with no new signature. Module tidy
passes. Erlang/login docs pass; version docs retain five inherited findings.
All three human Scenarios remain byte-identical.

## Fixture correction, integrity and limits

The separate strict AMQP attempt `20261109T230749-65cf0b` stops during broker
readiness before any console/native/module execution. Actual vendor logs record
cookie EACCES. A controlled native replay on both pinned images demonstrates
that a root health CLI after the vendor ownership scan creates root-owned
mode-400 cookie; broker-user authentication fails. Running that same CLI through
vendor gosu creates broker-owned cookie and authentication succeeds. The live
failure's ownership/interleaving was not captured before teardown. Both health
commands now use the broker user; both functional profiles are requalified
because their shared Compose input changes. This setup failure is not added to
the module-failure counts.

Exact earlier input variants and explicit deltas remain retained. The first
diagnostic spec is reconstructed by reversing two braces and matching its
immutable hash; later selected originals were copied before edits. Completion
adds decoder/native controls (41→43); lifecycle adds three existing dependency
files (43→46). Final Erlang changes only shared Compose relative to its earlier
passing 46-input run. AMQP retains 43 keys while strengthening positive assertions
and repairing the health fixture. No identical whole-campaign input claim is made.

The worker independently audits all 43 containers, 23 volumes and ten networks
absent across ten attempts, plus two separate native projects. The parent
independently audits both imported final projects and their five recorded
volumes. The durable `rabbitmq-erlang-20261109-49e8ade0848` export preserves
all nine raw run parents, exact sources/captures, diagnostics, native ownership
controls and five patches. All **1,152** checksums are independently reread by
the parent; manifest SHA-256:
`aeb77f93e779923aef4c757e3428d872b0aab36c8a513ba2fbd93074aef80d22`.

AMQP 1.0/non-RabbitMQ, other SASL/TLS/client certificates, clusters and IPv6 are
unqualified. Erlang Windows, Linux x86, other stager flavors, TLS distribution,
EPMD, CouchDB and other releases remain unqualified. Unicode packet construction
and result decoding do not prove arbitrary Unicode shell semantics. Declared
hashes are not the whole dependency graph. No shared runner, project dependency
or timeout changes were needed. The aggregate selector is
`tmp/module-target-checkpoint-rabbitmq-erlang-current.json`; Grafana and
WordPress admin remain unqualified, while Solr has separate work in progress.
