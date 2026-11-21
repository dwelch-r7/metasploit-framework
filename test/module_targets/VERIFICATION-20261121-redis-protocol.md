# Redis protocol bytes and credential-consumer verification

Observed 2026-11-21. Five real Redis consumers qualify the stated package and
authentication/data paths. The full valuable feasible-module goal remains active.
The [profile documentation](redis_protocol_utf8/README.md) supplies the guarded
command, pinned image, synthetic credentials, controls and remaining limits.

## Native prerequisites and actual consumers

The two new profiles use the genuine Ubuntu Redis `5:6.0.11-1` package as UID101.
One service runs at a time with 128 MiB RAM/swap, 0.5 CPU, 64 PIDs, read-only
root, bounded tmpfs and random loopback publication. Package/binary/library
identity, correct/incorrect native authentication, native shell/Lua operation,
complete configuration and serialized database snapshots gate all owning calls.

Stock Redis commands seed and independently read Unicode keys, NUL/CRLF bytes,
trailing whitespace, empty strings, lists, sets, sorted sets and hashes. A native
SAVE proves the Unicode output path and exact RDB payload bytes before the
upload owner runs. Original daemon identity, all configuration values, serialized
keys in databases0/2 and a foreign file must preserve after each operation.

Actual entry points cover:

- `redis_server`: INFO/PING with console credentials and typed UTF-8 datastore
  credentials, observing actual service reporting calls.
- `redis_login`: successful, incorrect and recovered successful login statuses
  using the same selected module and real LoginScanner results.
- `redis_extractor`: exact scalar/structured returns and real CSV loot twice.
- `file_upload`: two Unicode filenames, exact physical RDB bytes/UID and full
  configuration/key recovery, repeated on one selection.
- `redis_debian_sandbox_escape`: two genuine id-based checks with typed UTF-8
  credentials. Existing Lua profiles separately replay default Bash sessions,
  exact command delivery, incorrect-auth recovery and patched AutoCheck refusal.

The Unicode password has nine characters and twelve UTF-8 bytes. Console parsing
can already produce binary strings; explicitly typed Ruby/API datastore strings
expose the character-count defect without replacing a module method. Passive
tracing records the original argument encodings, wire bytes, authentication
returns, data-reader returns and report calls. Reporting-database persistence is
not claimed.

## Observed original and repaired behavior

| Protocol profile | Corrected original examples/failures/pending | Repaired | Repaired seconds |
|---|---:|---:|---:|
| `redis_protocol_ascii` | 7/2/0 | 7/0/0 | 127.78 |
| `redis_protocol_utf8` | 7/5/0 | 7/0/0 | 95.50 |

The original ASCII profile exposes a real unclassified short WRONGPASS reply
and truncated trailing data. The Unicode profile's typed authentication fails
across all five consumers despite successful independent native authentication.
Native readiness and complete final preservation pass in both original frames.
The strict assertions remain enabled after repair. All frames have zero pending
and outside-example errors.

The three existing Lua profiles also pass against the repaired shared libraries:

| Existing profile | Examples/failures/pending | Seconds |
|---|---:|---:|
| `redis_lua` | 9/0/0 | 147.63 |
| `redis_lua_open` | 9/0/0 | 119.27 |
| `redis_lua_fixed` | 6/0/0 | 50.73 |

Thus the verified five-profile matrix has **38/0/0**. Six additional actual
native/owning Bash sessions are fully used and closed, including four original
owning sessions. The protocol-only profiles do not create OS sessions.

## Source repair and focused regressions

Commit [`a2520d401899`](https://github.com/dwelch-r7/metasploit-framework/commit/a2520d4018996731ed3384a53d17951e2e9ae290)
changes four library files. One serializer in the existing Redis component emits
binary RESP bulk strings using byte lengths; the two existing wrappers delegate
to it and preserve their nil/empty contracts. Mixed UTF-8/binary logging also
preserves input bytes. Removing only the final response CRLF replaces destructive
whitespace stripping; binary parser offsets and zero-length bulk handling retain
empty nested values. WRONGPASS classification recognizes the observed Redis6
short form and Redis7 punctuation while preserving the existing named capture
and rejecting incomplete/unrelated replies. Module sources, metadata, targets,
payload defaults and exploit dispatch remain unchanged.

Identical frozen source-level inputs reproduce **174 examples/28 failures**
before repair and **174/0** afterward across six serial files. This includes
61 Redis-library examples, 71 existing upload/Lua examples and 42 repeated eager
support examples. The parent's combined seven-file suite passes **143/0**:
61 library, 71 upload/Lua, four readiness and seven support examples. These are
two views of overlapping coverage, not 317 unique examples.

Fixtures retain original stock redis-cli AUTH/PING request captures and actual
server responses for empty, trailing and nested values. A separate real Redis
7.2.4 capture verifies modern WRONGPASS punctuation. The request collector sends
canned ACKs solely to capture stock-client bytes; no module interacts with it,
and no module verdict depends on its ACKs. Native consumer gates and response
fixtures use the real server. The [RESP specification](https://redis.io/docs/latest/develop/reference/protocol-spec/)
defines byte-counted binary bulk strings.

## Separate setup and assertion findings

The first original run retains **14/8/0**, including one harness encoding error
when comparing binary console output with a UTF-8 upload filename. Physical
upload proof already succeeds. Comparing the exact binary bytes corrects that
assertion; the repeated original run retains the real **14/7/0** failures above.

The first repaired five-profile run retains **38/1/0**. Its ASCII extraction
fails because the test's CSV auto-detection selects an embedded quoted CRLF as
the row separator when SCAN happens to put that value first. The captured loot
is valid with the producer's LF separator. Reading those same files with explicit
LF preserves exact Unicode/NUL/CRLF/empty/tail bytes; both protocol profiles
then replay at **14/0/0**. The criterion is preserved, and the failing frame is
kept. The UTF-8 profile had already passed in that first repaired frame.

An earlier source-unit fixture omitted `rex/text`, producing two setup failures;
the final identical 174-example pair loads that existing prerequisite. Two
late diagnostic sockets attempted already-cleaned endpoints and were refused;
they supply no module verdict. Dedicated live pilots provide the retained raw
fixtures instead. No protocol/session stubs enter the functional profiles.

## Evidence, cleanup and limits

Private raw evidence is under `tmp/redis-protocol-feasibility/`. Original wrappers
are `tmp/invoiceshelf-feasibility/functional-20261121T204152` and
`functional-20261121T205220`. The first repaired wrapper is
`functional-20261121T211348`; the corrected protocol replay is
`functional-20261121T212331`, with runtime
`tmp/module-target-tests/20261121T212332-68f42f/`. Original source/fixture pairs,
native journals, real loot, passive events, input snapshots and all attempts are
retained locally. Runtime input hashes remain unchanged during every frame.

The passing set reaches **176 cases / 43 profiles / 482 current inputs**, with
92 retained ordinary sessions and 21 separate candidate-source sessions. This
does not imply that all registered modules or paths pass. All 44 cgroup captures
across the eleven functional profile executions show zero OOM/PID events.

All **25 new / 806 recorded Docker objects** are independently absent. Global
inventory in both Docker contexts includes stopped containers and is empty.
No unused unrelated container was found at resume or finish. All callback ports
4492-4495 are closed; no local console/guard or delegated worker remains active.
The observed global container peak is one. No images, caches or daemon settings
are changed. The shared lifecycle policy requires namespaces, exact resource
tracking, cleanup on every exit and global checks for tool-created helpers.

Changed source/unit Ruby retains **61 inherited lint offenses, zero new**,
down from 64. The three new acceptance/helper Ruby files pass lint. Module-doc
tidy retains existing warnings in `redis_server`, `redis_login` and
`redis_extractor`; upload/Lua docs pass. No new doc warning is introduced, and
all 20,558 human-written Scenario bytes are unchanged. Full-suite or CI success
is not inferred from these targeted checks.

Fragmented/malformed responses, large data, limits, TLS, nondefault ACL users,
extra releases/platforms and reporting databases remain unqualified. Lua dropper
and its wget/CPU prerequisites remain open. Missing-library/nil-command Safe
classifications retain their earlier limits. Other valuable feasible modules,
including earlier ProjectSend failures, remain in scope. No PR or external
comments are created.
