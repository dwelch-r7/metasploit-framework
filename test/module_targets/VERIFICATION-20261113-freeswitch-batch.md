# FreeSWITCH multi-host validation — 13 November 2026

## Summary

Current input-matched checkpoint: **222 qualified modules, 243 profiles and
2,335 functional examples**. The broader campaign remains active. No PR is
created.

The two confirmed FreeSWITCH defects are repaired: Scanner dispatch precedes
per-host AutoCheck, and failed login updates match the attempted service and
supplied credential identity/type. The isolated source commit is
`9c5716152485a6d6c9bf88f24ad207dc9c2ecff8`, imported as `715c6512373`.
The final ten-profile replay tests frozen revision
`decb9aa4bd604af29cd66e515cd671bf2028b230`: **80 of 81 examples pass**.
One concurrent reporting case exposes a separate installed dependency defect.

## What looks good

The [multi-host fixtures](freeswitch_batch/README.md) run two independent, pinned
FreeSWITCH 1.10.10 services. Profiles select identical passwords, different
passwords including Unicode/spaces, or a loopback-only ACL on the second service.
Two-service profiles use four containers capped at 2,432 MiB, 3.3 CPUs and 832
tasks. Single-service profiles use three containers. External regression profiles
resolve to at most five containers. One profile runs at a time through the
resource guard; application ports publish only on loopback.

Independent framed-protocol and local `fs_cli` controls run before and after
module calls. The reporting PostgreSQL container supplies a separately verified
closed event-socket port while its SQL health check succeeds. Binary and
configuration hashes, engine identity and voice state remain checked. Passive
packet capture and direct SQL joins establish actual requests, responses and
stored credential state.

| Final replay scope | Examples | Failures |
| --- | ---: | ---: |
| Four single-host FreeSWITCH profiles | 25 | 0 |
| Two hosts with different passwords | 5 | 0 |
| Two hosts with mixed ACL access | 5 | 0 |
| Two hosts with identical passwords | 6 | 1 |
| PostgreSQL, SSH and HTTP credential reporting | 11 | 0 |
| RabbitMQ version/login/reporting | 17 | 0 |
| MSSQL authentication capture | 12 | 0 |
| Total | 81 | 1 |

The seven FreeSWITCH profiles execute 81 public module calls with 81 verified
wire captures and 26 independent native phases. All native controls pass.
Forty-eight FreeSWITCH resource-counter queries show no memory-limit, OOM or
PID-limit events. The first console starts cold with two freshly generated
metadata files; subsequent consoles reuse only the same invocation's cache.

The final identical focused source suite changes from 46 failures to zero
across 73 examples: 41 proxy cases, 11 real Scanner dispatch cases and the prior
21 transport checks. The parent repeats all 73 successfully. The existing
43-example AutoCheck suite also passes in the worker. Fixtures retain real
Scanner/RhostsWalker/replicant/thread dispatch and AutoCheck; TCP I/O and database
persistence are boundary doubles in these focused units. Container tests supply
the separate real wire and SQL evidence. Earlier fixture-invalid drafts and
corrected original/fixed receipts remain preserved.

Module/spec strict lint, syntax, module tidy and documentation tidy pass. Strict
proxy lint remains nonzero for 16 exact pre-existing sibling/module offenses
(original: 21); there are no new or touched-code offenses. The other three proxy
methods, shared Scanner/AutoCheck/DBManager/service APIs and complete human
Scenarios tail remain byte-exact.

All ten profiles complete teardown. Ninety-four independent cleanup queries
verify all 38 containers, 10 networks and six volumes absent, plus an empty
global container inventory. The manager/controller exits 1 for the single
recorded test failure; the observer exits 0. All three process IDs are absent.
The tool-container guard retires normally with exit 0 and both advisory locks
free. It also removes four unrelated auto-started tool containers during its
lease.

## Concerns

The identical-password `THREADS=2` case remains unqualified. Both genuine
services accept `ClueCon`; simultaneous reporting creates competing
password-only credential cores. One insert fails with `Private is already taken
for credential cores with only a private credential`, leaving only the other
service's successful login. This is a source failure, not a fixture failure;
all controls and teardown pass. The profile's original failing result is retained
and excluded from the qualified checkpoint.

The actual Framework image's `metasploit-credential` 6.0.26 creation source has
SHA-256 `ed58728d9ba54fb41dc2d9783da20c032051d8134467bcf485150dbd52d8298e`.
Its filesystem layers match the failing profile. Source inspection finds `core`
cached outside `retry_transaction` and reused through `||=` after a uniqueness
failure. The proposed dependency fix would select/reset the core on every
retry, preserving cracked-password origin lookup. That fix is deferred and has
not been implemented or tested. No module workaround or dependency change masks
this failure.

Historical MySQL capture and NiFi discovery results also remain pending at the
changed shared-file hash. Their current topologies exceed the five-container
limit and need bounded profiles before fresh replay. No hash exemption keeps
those results qualified. The current count is therefore lower than the prior
225-module checkpoint. The three earlier Druid JavaScript, Superset owner-RCE
and WordPress admin exclusions remain unchanged.

## Suggestions

Split the MySQL capture and NiFi discovery matrices into bounded profiles and
replay them. Investigate the credential dependency with a deterministic losing
insert followed by a competing persisted winner; verify real retry/validation
behavior without sleeps or an owner-level workaround. The companion FreeSWITCH
execution module and its Linux delivery/session families remain separate work.
The inventory still has 277 pending documented container hints and no stale
reviews; missing hints do not establish infeasibility.

## Preserved evidence

The original `c4ed9d168c5` run `20261113T130153-010890` records 16 examples,
18 public calls, 12 global AutoCheck resolver failures and two wrong-service
credential-status failures, with no fixture failures. Native controls pass and
27 independent cleanup queries pass. Its seal contains 296 entries and 67 pinned
inputs, manifest SHA-256
`f5432be3cad9a1417bb6841c0c071676477546480cbd5667100fac726ba417bc`.
Shared proxy/service inputs are explicitly tracked by the fresh manifests.

The source worker seal contains 516 entries, manifest
`2c04dd9e868ccfb3d58abdad23d5b2e7a092cb176c002a47335d2211e4f118ae`.
The parent source review seal contains 558 entries, manifest
`730b5156ee273efb90f437e6de3384a7c0cb40245c156c55478fb9ccb9d6f29f`.
Final run `20261113T135257-bb0570` is sealed with 1,125 entries and 153 pinned
inputs, manifest
`70b0f4f79291975b2b81f92083557498ae17a91d7bbdc2f6e335c37aa7d12efc`.
Every sealed entry is independently verified, read-only and single-linked.
