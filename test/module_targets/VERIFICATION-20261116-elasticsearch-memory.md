# Elasticsearch memory disclosure qualification, 2026-11-16

One new runtime owner, five profiles and 28 functional cases bring historical
campaign coverage to **265 runtime owners in covered paths, 441 profiles and
3,577 functional cases**. These five profiles are current; earlier campaign
coverage remains historical and was not replayed. The broader campaign remains
open. No PR is created.

All **76 public calls** pass: 26 `check` and 50 `run`, covering SCAN and DUMP.
Eighteen loot files match the rendered backing-buffer intervals in the same
call's actual HTTP responses. Sixteen vulnerability rows and sixteen service
rows remain correctly deduplicated across repeated calls. Seventy independent
native HTTP controls verify the actual application, JVM heap, permissions and
unchanged ordinary document. All twenty before/after container counter rows
show zero OOM, OOM-kill or PID-limit events. Sessions and jobs finish empty.

## Native target and memory controls

The official immutable images run Elasticsearch 7.13.2 and 7.13.4 on Linux amd64;
Framework runs locally with Ruby 3.3.13. The
[vendor advisory](https://discuss.elastic.co/t/elasticsearch-7-13-4-security-update/279177)
identifies 7.10.0–7.13.3 as affected and 7.13.4 as fixed. The ordinary native
index/document API succeeds on both versions before module classification.

The affected release's normal allocator is unpooled at heaps of at most 1 GiB.
A 1,280 MiB heap activates its normal pooled allocator without private flags or
server modifications. The paired native probes use the same resource settings:
all four affected probes expose an earlier HTTP 200 index-creation response,
absent from their current two-byte malformed JSON request. Fixed probes expose
no backing array and identify a `ByteArrayInputStream`. The specific seeded
document canary is absent on both; that does not negate the demonstrated earlier
response disclosure. The low-heap profile separately validates the unpooled
buffer's HTTP framing outside the current JSON body.

Real native roles matter: read-only accounts are denied document writes, and
one is also denied cluster information. Both can still trigger malformed bulk
parsing. An original limited-account public SCAN also exposes a previous demo
administrator Authorization header absent from its own request. Collection
therefore does not depend on a successful passive version check. Anonymous and
incorrect-password attempts must return actual HTTP 401 responses and create
no loot or vulnerability report.

## Source corrections and failure attribution

Three defects are reproduced through original public entrypoints: 403/404
version responses cause `nil.dig`; SCAN/DUMP on the fixed release cause
`nil.split`; and `run` treats a multi-host `RHOSTS` value as one literal hostname.
Public `check` already iterates those same hosts correctly. The correction
guards parsed response types/frames, skips absent disclosure data and uses the
existing Scanner `run_host` callback. Native bulk denials get a precise failure
reason. A nonexistent-index bulk route remains usable; it must not be confused
with an actual missing handler or blocked through version-check gating.

The same 25 focused unit cases have twelve failures with original source and
zero with corrected source. Transport-stubbed unit cases include genuine native
captures and explicitly derived type/boundary variants; they add no functional
coverage. Public functional calls and native controls supply the runtime proof.
Earlier fixture faults remain separate: Python name shadowing, confusing exec
UID with the Java process UID, a cold-start readiness deadline, an unsupported
RSpec matcher and Ruby keyword argument passing. They are preserved separately
and are not labelled module failures. Negative functional oracles were tightened
and all five profiles replayed with their final current input files.

Original owner SHA256:
`2951e20ce76fb37be25dc851eff49499d44ca57408a965eca7d1ec7e9de0e7c9`.
Qualified owner SHA256:
`6601c9baebf89fd5f0380626c8e255d8f5c315e71259a5af9442e7583b3911c1`.
The human-written whole module guide and Scenarios remain byte-identical:
`c05de3e25645541a5fb8856b450ba28a0b0f136e54ffb8e220a0b3cd623a37b7`.

Source and fixtures are committed as `d10dca7cf5d193576af40419faf3765869c6961b`.
All 58 consumed input blobs match that commit. Runtime records retain their
actual earlier HEAD and tested working-file hashes; this does not claim an
earlier checkout of a commit created afterward. The independent worker's
40-entry final unit seal is
`/Users/dwelch/.codex/reports/elasticsearch-memory-contract-unit-20261116T131515`,
manifest SHA256 `96af88ed58dffffad480324b2a831f346226e630f2aa6c2b4d8b91314e06d366`.

## Functional results

| Profile | Actual run | Cases | Public calls | Native HTTP | Loot files |
| --- | --- | ---: | ---: | ---: | ---: |
| `elasticsearch_memory` | `20261116T132525-90f912` | 8 | 20 | 10 | 4 |
| `elasticsearch_memory_fixed` | `20261116T132812-a0479d` | 4 | 8 | 10 | 0 |
| `elasticsearch_memory_secured` | `20261116T133023-b8e463` | 9 | 34 | 36 | 10 |
| `elasticsearch_memory_unpooled` | `20261116T133337-0ae4a8` | 4 | 8 | 10 | 4 |
| `elasticsearch_memory_unrelated` | `20261116T133551-d9e8d5` | 3 | 6 | 4 | 0 |

Each stack has exactly two capped containers, loopback-only published ports,
PID limit 128, init enabled and equal memory/swap limits. Normal application
memory is 2 GiB, with PostgreSQL at 384 MiB; the low-heap and unrelated profiles
use less. The five serial stacks finish cleanup before the next starts. Every
project, attached volume and network is independently verified absent afterward.
Two automatically restarted GitHub/AWS connector containers are removed during
the final matrix under the user's explicit instruction. Maximum work containers
is two; maximum observed global containers is three. Final Docker inventory is
empty and the advisory lock is free. The committed guard refuses unrelated
containers; automatic removal is this campaign's personal orchestration policy.

All five runtime archives have exact file sets, with 401 entries independently
rehashed. The qualified checkpoint is recorded under
`/Users/dwelch/.codex/reports/elasticsearch-memory-qualified-checkpoint-20261116`.
The [lab README](elasticsearch_memory/README.md) documents one serial guarded
command for all profiles and the source/image pins. Reusing its per-invocation
metadata cache shortens repeated console setup.

## Review and remaining limits

New unit/functional specs and fixture Ruby have zero lint findings. Original
and final module strict RuboCop both exit 1 with the same pre-existing duplicate
`RPORT` warning; msftidy exits 2 before and after. No blanket lint pass is claimed.
Syntax, Compose resource/binding resolution, input hashes and diff checks pass.
Read-only source/fixture/evidence review finds no remaining material issue within
this scope.

Dump files preserve the existing rendered format, including duplicate root/top
reason fields, closing quotes and truncation annotations. They are not a complete
raw backing-array dump or a count of unique disclosed bytes. Other releases,
TLS/IPv6 transports, other platforms and unobserved buffer-content variants
remain unqualified. The static queue has 5,179 source files, 4,622 candidates,
266 registered owners and 4,333 pending reviews, including 239 container hints.
Twenty-six individual reviews have no stale source hashes. The historical
one-owner difference between registration and runtime qualification remains.
