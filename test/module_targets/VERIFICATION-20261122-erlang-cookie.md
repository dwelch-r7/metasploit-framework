# Erlang cookie command and session validation

The frozen original pair retains **18 examples / 2 failures / 0 pending**;
the repaired pair passes **18/0/0**, with zero errors outside examples. The
owning module is the sole changed declared input. The complete valuable
feasible-module inventory goal remains active.

| Serial profile | Genuine broker/runtime | Candidate cases | Candidate sessions |
| --- | --- | ---: | ---: |
| [erlang_cookie_old](erlang_cookie_old/README.md) | RabbitMQ 3.8.16 / OTP24 | 9 | 6 |
| [erlang_cookie_new](erlang_cookie_new/README.md) | RabbitMQ 3.12.14 / OTP25 | 9 | 6 |

## Genuine prerequisites and source defect

The pinned official images and [shared native controls](rabbitmq/README.md)
verify real broker/OTP identities, AMQP TCP/TLS behavior, actual distribution
handshakes, correct/wrong cookies and vendor `erl` RPC execution. Benign native
background programs complete, remove their files and disappear from `/proc`
before owning tests. Native stock-handler Bash and Linux x64 Meterpreter
callbacks independently establish each payload family before owner execution.
The application code is unmodified; serial profiles enable Docker init.

The module previously sent UTF-8 octets as an Erlang character list. Native
`os:cmd` then encoded those characters again, corrupting non-ASCII text. Actual
native `term_to_binary(unicode:characters_to_list(...))` captures provide separate
ASCII, Latin1 and wide-character references. Historical byte-list captures stay
intact and are identified as structural references rather than proof of correct
Unicode command execution. The official [os:cmd contract](https://www.erlang.org/docs/25/man/os.html#cmd-1)
and [ETF definitions](https://www.erlang.org/docs/25/apps/erts/erl_ext_dist.html#string_ext)
explain the character-list and byte-string distinction.

The focused repair preserves ASCII framing, public signature, the input byte
limit, authentication, stager completion and disconnect behavior. It emits
compact character terms for Latin1 and integer lists for wider scalars, respects
explicit Ruby encodings, accepts frozen UTF-8 payload bytes, retains legacy
non-UTF8 binary interpretation and rejects tagged invalid Unicode/NUL commands.
No dependency or shared protocol-library behavior changes.

## Functional evidence

Each release tests 13-, 255-, 256- and 65,535-byte commands twice, exact rich
quotes/Unicode/CRLF twice, the 65,536-byte refusal, wrong cookies and two fresh
owning sessions per supported family. Vendor RPC counterparts precede finite
commands. The native 65,536-byte command succeeds before the owning limit is
verified as an explicit refusal. Rich-command input bytes are independently
read back from the public module datastore before normal execution.

Session proofs correlate actual owner/payload, UID999, target PID, kernel birth
value and exact file bytes. Public session APIs produce fresh responses before
shutdown; native `/proc` checks then prove PID disappearance and Framework
registrations are removed. Temporary-file sets, source hashes, service health
and empty Framework sessions/jobs verify afterward. There is no reporting
database in this lab; database session-row closure is not claimed.

The candidate has twelve used/closed sessions: four native and eight owning.
The original frozen pair independently has twelve more. Nine earlier diagnostic
sessions retain separate successful lifecycle proofs without qualifying their
unsuccessful whole profiles. All 33 are ordinary payload sessions. The current
retained set reaches **315 cases / 67 profiles / 702 byte-verified inputs** and
**252 ordinary used/closed sessions**, with 21 separate source-variant sessions.
The preceding 687-input checkpoint remains byte-identical.

## Failures retained separately

The first launcher attempt timed out on read-only Docker inventory before any
guard, observer or container started. A healthy empty inventory preceded retry.

An initial native rich-command control used `binary_to_list` for UTF-8 bytes.
It produced mojibake before any corresponding owner call. That draft retains
9/1/0 and six used/closed sessions; it is a native oracle failure.

The next native control used the correct Unicode conversion and wrote exact
bytes. Literal newlines in an inline console option then split console input,
causing parse errors and desynchronizing later calls. That draft retains 9/2/0
plus one hook error; three earlier Linux sessions have valid completed proofs.
Setting the actual datastore through its public API, verifying Base64 input
and keeping the console request on one physical line repairs the fixture.

Only the resulting clean original pair establishes the source bug: both native
outputs are correct, both owning outputs show the same UTF-8-to-Latin1-to-UTF-8
corruption, all other eight cases per release pass, twelve sessions close and
both final states preserve. The repaired pair keeps every assertion/recipe
unchanged and passes all eighteen cases. Child units separately caught and
corrected an intermediate `Msf::Encoding` constant-shadowing error.

## Checks, resources and remaining scope

Frozen source regressions retain **65/7 to 65/0** with identical assertions and
vendor vectors. The protocol library file passes48/0. Root independently repeats
both files at65/0 and48/0, including shared eager support examples. A first root
attempt used an empty private config without the required test database setup;
it loaded zero examples and is excluded. Normal configured runs pass. Syntax
and msftidy pass; changed Ruby has zero new offenses and eleven inherited owner
offenses. Module-document tidy is clean; human Scenarios remain unchanged.

The shared guard keeps one release active at a time: broker768 MiB/1CPU/256PIDs,
native client128 MiB/0.25CPU/64PIDs, Framework1536 MiB/1CPU/256PIDs, with swap caps.
The completed client is removed before owner calls, leaving two containers.
Each complete namespaced project and its volumes is removed before the next.
Two unused automatically initialized connector helpers appeared after a finished
lab and were explicitly identified and removed before another stack started.

Both Docker contexts finish globally empty, including stopped containers.
All **34 new/1,032 recorded resource IDs** are absent. A supplemental one-broker
pilot also proves the stronger native completion gate without Docker init.
Its container/network IDs are absent, but its anonymous-volume ID was not
captured before prompt teardown; historical event queries timed out. Current
global volume names are a subset of the pre-Erlang snapshot, proving no newly
created volume remains. That unrecorded ID is excluded from exact-ID counts.
No unrelated volumes are removed, and no image/cache pruning or daemon restart
is performed.

The frozen candidate runtime is `20261122T045820-adb076`; original runtimes are
`20261122T042559-2b9aca` and `20261122T043449-89989d`. Receipts retain input hashes,
source binding, vendor RPCs, exact commands, session/PID proofs, raw console and
RSpec JSON, final preservation and independent cleanup. Functional RSpec time,
including controls, is149.96 and134.41 seconds for the candidate releases.

The stock images explicitly report `telnet=ABSENT`; the owner's default double
reverse payload is therefore a separate prerequisite gap. These profiles choose
Bash and Linux x64 printf delivery. Windows, Linux x86, other stager flavors,
other releases, TLS distribution, EPMD discovery, CouchDB and full ancestor-
process/socket preservation remain unqualified. The original combined profile
is not newly qualified by these serial results.

**Summary:** Repairs a native-proven Unicode bug and qualifies stated owner paths.
**What looks good:** Frozen source comparison, genuine native controls and physical
session closure, with immediate helper/stack cleanup.
**Concerns:** Wider target/payload paths and the supplemental volume-ID recording
gap remain explicit.
**Suggestions:** Continue the full source inventory and investigate remaining paths.
