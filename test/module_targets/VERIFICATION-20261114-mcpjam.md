# MCPJam Inspector execution and default boundaries

The covered paths of `exploit/multi/http/mcpjam_inspector_rce` pass against four
genuine official images. The cumulative campaign record advances to **246 modules
qualified in covered paths, 307 profiles and 2,912 functional examples**. This
invocation replays MCPJam; earlier qualifications retain their recorded inputs
and evidence. The broader campaign remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb mcpjam mcpjam_loopback_143 mcpjam_loopback_146 mcpjam_token
```

| Profile | Original target default | Cases | Public calls | RSpec duration | Result |
| --- | --- | ---: | ---: | ---: | --- |
| `mcpjam` | 1.4.2, network reachable and unauthenticated | 11 | 22 | 198.55 s | Pass |
| `mcpjam_loopback_143` | 1.4.3, loopback bind | 5 | 10 | 56.69 s | Pass |
| `mcpjam_loopback_146` | 1.4.6, loopback bind | 5 | 10 | 61.98 s | Pass |
| `mcpjam_token` | 1.5.0, Docker bind and session authentication | 5 | 10 | 54.68 s | Pass |

Run `20261114T173807-07b8ee` and its original controller exit zero. All four
RSpec reports have zero failures, pending cases and outside-example errors.
The serial invocation takes 450.49 seconds including builds, a cold first
console and teardown. Later profiles reuse metadata generated within this
invocation only.

## Native target fidelity

The [recipes](mcpjam/README.md) and [vendor manifest](mcpjam/vendor.json) pin image
digests and installed bundle hashes. Original npm startup, the installed MCP SDK
and Node run as UID 1000. Installed source-map originals match pinned vendor
sources at commits `af9cf6a62f550e986fe330c09b8a3b8b83136df6`,
`20dbeb51943b458d429a80dcc850c2b16a53972e`,
`ca9839e80254fd3326246f1b68dc2a139b49d6fa` and
`069465fb6b4730497641bd4dd8db9b12924ac2c3` respectively.
No application route, production owner method, vulnerability or session is
simulated. No model/provider account is required.

Each profile independently verifies application/Node/SDK/bundle identity,
localhost and interface reachability, malformed unauthenticated connect behavior,
real SDK Unicode command output, Unicode-ID deletion and native process removal.
A separate genuine stdio server remains connected throughout owner operations;
its complete registry entry and process identity must remain unchanged.
The final invocation records 472 successful native probe processes, including
real reporting-database queries, and 131 native HTTP/control requests.

The [reviewed advisory](https://github.com/advisories/GHSA-232v-j27c-5pp6)
lists affected releases through 1.4.2 and a 1.4.3 fix. The
[vendor change](https://github.com/MCPJam/inspector/commit/e6b9cf9d9e6c9cbec31493b1bdca3a1255fe3e7a)
changes the default bind to loopback. Genuine 1.4.3/1.4.6 images refuse interface
connections while their localhost API still executes native controls. Those
profiles are remote negatives; no proxy or bind override manufactures a positive.
Version 1.5.0 returns HTTP 401 to the unauthenticated owner. Its genuine localhost
administrative token is used solely for native controls and is never passed to
the owner.

## Public module behavior

All 52 calls execute the actual public check/run path. Check observations comprise
22 reason-bearing Vulnerable, 16 Unknown and eight Safe results; six attempts
explicitly disable AutoCheck. AutoCheck guards and forced tool/direct execution
are exercised independently on each boundary profile, without target artifacts
or sessions. Refused loopback access remains inconclusive remote detection.

The affected suite repeats exact ASCII/Unicode commands, Unicode server IDs,
output and quiet tool modes, and direct shell delivery. Exact native file bytes,
UID and process/registry restoration establish execution; HTTP 500 or a missing
direct-shell response alone does not. Rejected existing-ID attempts retain the
unrelated connection and create no command artifact.

Eight actual sessions cover Node command shells and Linux x64 HTTP-fetch
stageless Meterpreter through both `mcp_tool` and `direct_sh`. Public session APIs
prove responsive remote use and exact marker writes. Independent target PID,
ancestry, UID and file observations agree with real Framework session/database
records. Remote session exit is verified before Framework transport closure;
all owned processes, sessions, jobs and fetched files are subsequently absent.
Every case repeats from the same console module configuration using Framework's
normal execution replicants. Same-instance retries are covered by focused contracts.

All 124 recorded JSON-body observations have byte-count framing. Refused
connections are not claimed as transmitted requests. Reachable Unicode operations
reach the genuine API and produce exact native artifacts.

## Confirmed source defects and harness failures

Original run `20261114T170823-d33597` passes two of five cases and fails three.
Unicode command JSON declares 160 characters for 163 bytes and receives HTTP 400.
Unicode IDs also break connect framing and use an unescaped DELETE path. A
failed existing-ID start unconditionally deletes the unrelated connection.
Commit `8ce8ea47d1b531711f2b0cfd2a050aabe9569345`, developed in a separate
worktree, normalizes valid UTF-8 without mutating inputs, serializes JSON as bytes,
encodes the ID path segment, and cleans up only a natively acknowledged connection
owned by that attempt. Cleanup connection errors are reported without masking
the primary result.

The identical focused suite gives **25 examples / 19 failures before** and
**25 / 0 after**. The real Rex serializer changes an identical body from
145 declared / 148 actual bytes to 148 / 148. HTTP/application boundary variants
are doubles in that focused suite; genuine acceptance is recorded separately.
The primary checkout independently passes the same 25 examples. Strict RuboCop on
all seven changed Ruby files, module/documentation tidy, Node syntax and diff
checks pass.

Earlier native collision controls incorrectly assumed all releases reject an
existing ID. Version 1.4.6/1.5.0 intentionally replace it; version-aware native
controls subsequently pass. An observer initially mislabeled Ruby keyword-hash
HTTP calls, and an absent-artifact read obscured a Unicode failure. Both harness
errors are recorded separately from the original wire/ownership defects.
Fixed five-case replay `20261114T172917-06472b` passes before session expansion.

Eight-case run `20261114T173203-c9eaba` has seven passes and one cleanup-order
failure after a real usable Node shell exits: its transport remains until the
Framework peer closes. Subsequent wrapper closure restores the baseline and the
foreign-collision case passes. The harness now measures remote exit, closes the
Framework transport, then verifies the entire process ancestry is gone. No new
module defect is inferred from that ordering failure.

Human Scenarios through EOF are preserved byte-for-byte, SHA-256
`887694736281e35dc330d2cc926a8473e962a7c75484d16a24cf5ed1bb859e06`.
Two documentation-only corrections follow acceptance: one relative Markdown link
and the distinction between console reuse and execution replicants. Both are
explicitly reviewed; all executable/configuration inputs remain identical.

## Resources and retained evidence

Each profile uses three capped services on an internal network with no host
ports: Inspector 512 MiB / 0.75 CPU / 192 PIDs, Framework 768 MiB / one CPU /
256 PIDs, and PostgreSQL 128 MiB / 0.2 CPU / 64 PIDs. All 24 cgroup queries show
zero OOM/PID-limit events and no container is OOM-killed. The common serial guard
tears down each project before starting the next.

All 29 independent exact-ID/project/global queries confirm removal of twelve
containers, four networks and no named/image volumes. Docker is empty and the
shared lock is free. No unrelated image or volume pruning is performed.

The read-only accepted archive is
`/Users/dwelch/.codex/reports/mcpjam-qualified-20261114`: 340 files,
64 selected inputs, MANIFEST SHA-256
`f52fd73f7951d8d52a00e3512c5237bba8d774a6043339ad61a480afba7ae61f`.
Raw evidence, original/fixed focused tests, static checks and cleanup receipts
are retained. Earlier immutable failure archives remain separate:

- Original source failures: `mcpjam-original-owner-failures-20261114`, MANIFEST `e7c0d06d66c731a8939058187c016b60d82762108a3cd63e5f4a8fc0b3ecd860`.
- Session cleanup ordering: `mcpjam-session-shutdown-order-20261114`, MANIFEST `02b5f3fc1bc1c840aba53a3d0ed5f4759b3ea6ef073f01988fbd79b348febffd`.
- Native first attempt: `mcpjam-native-first-20261114`, MANIFEST `8be0a7f1ea3132ea6894a6de099a8fc44893b34c8ce1a3b9a79d49d58fee2166`.
- Native collision diagnosis: `mcpjam-native-collision-diagnosis-20261114`, MANIFEST `1fe0f67f527478679ade5c11f1677578ff23aa85b28c43333787d4df23751ff3`.
- Expanded native controls: `mcpjam-native-remaining-20261114`, MANIFEST `f926542663234e000ec3b083ff6788365fac4e7076ed1cf8b71d9ccdb222d900`.

Static inventory records 5,179 source files, 248 registered owners, 22 individual
reviews, 253 pending documented candidates and zero stale reviews. Registration
alone does not establish successful execution.

## Review and limits

**Summary:** The tested default deployments, command paths and session families
work after the targeted Unicode/connection-ownership fix.

**What looks good:** Genuine independent SDK controls, exact effect evidence,
repeated sessions, foreign-state preservation and complete teardown agree.

**Concerns:** Other versions, TLS/proxies, architectures, staged payloads and
additional session families remain unqualified. Later vendor APIs may accept and
replace an existing ID; concurrent replacement and response-lost creates cannot
be safely owned through the ID-only DELETE API. The fix makes no broader claim.

**Suggestions:** Retain those scope limits and the standing deferred paths.
The previous published head's Linux Mettle acceptance records repeated
file-operation timeouts and cancellation near its 60-minute job limit; its cause
and relationship to this campaign remain unverified in [DEFERRED.md](DEFERRED.md).
This MCPJam native replay does not establish that CI issue is fixed.
