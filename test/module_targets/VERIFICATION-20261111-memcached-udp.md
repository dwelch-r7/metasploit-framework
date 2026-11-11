# Memcached UDP scanner validation, 2026-11-11

The checkpoint is **192 qualified modules, 137 profiles and 1,516 functional
examples**. This adds the UDP version and stats-amplification scanners and ten
examples. Static registration covers 194 sources, with 310 documented container
hints still pending review. The broader campaign remains incomplete.

The [lab](memcached_udp/README.md) runs official pinned Memcached 1.4.39 and
1.6.26 with UDP enabled, another 1.6.26 with UDP disabled, and canonical Framework.
Four containers are capped at 960 MiB and 1.3 CPUs in total: 64 MiB/0.1 CPU per
server and 768 MiB/one CPU for Framework. All share an internal test network;
the servers also use a public network for random loopback port publishing.
No host namespace, extra capabilities or source-address spoofing is used.
These are hard limits, not measured peak-memory claims.

## Genuine targets and independent controls

| Release | Official image digest | Observed image ID |
| --- | --- | --- |
| 1.4.39 | `sha256:f4504742a8fb03c3ac0cd172e1c1d2277117629f8d21d52f78307121ddc3de5f` | `sha256:bdb0ceca47d8eac5b0a41ea3993a10759066d754478a041930073aa3c4d2b443` |
| 1.6.26 | `sha256:09eaba8e0b136af2f1d8a4985b4fda74ce2793f95ea66d82fbe5769c05b42ea3` | `sha256:10895cbae2201dbd8d84c3c9047f79424e9ed1ccbe25884d1b4d795d0ac6d5fb` |

Before and after owning calls, a Ruby standard-socket client runs in Framework's
actual network namespace without loading Framework. It verifies TCP versions
and real `stats settings`, complete UDP version/stats responses on both enabled
releases, absent UDP responses on the still-working TCP-only server, and closed
UDP ports. The client checks the documented eight-byte request ID, sequence,
fragment-count and reserved fields and reassembles actual response fragments.
See the [official protocol](https://github.com/memcached/memcached/blob/1.6.26/doc/protocol.txt).

A separate passive AF_PACKET observer captures every actual module call using
the Framework container's ordinary NET_RAW capability. It does not replace any
module socket or server handler. Request bytes, transaction IDs, ports, response
fragment completeness and versions must agree. Amplification expectations use
the actual owning reply lengths, because stats counters change between requests.
Sizes describe UDP application bytes, including Memcached's header; no Ethernet
or IP bandwidth measurement is claimed.

The shared NTP acceptance observer retains service/vulnerability API arguments
and calls the real reporting methods. Its historical output filename remains
`ntp-reports.jsonl`. SQL persistence is outside this profile's claim.

## Preserved setup and harness failures

Each attempt reached an actual manager terminal and passed independent root
cleanup before its selected source was changed. No failure below establishes a
production-module defect.

| Run / source | Observed cause | Immutable files / checksum-manifest SHA256 |
| --- | --- | --- |
| `102719-59b9b8` / `297326cf9f0` | Docker reports `:0` publishing on this internal-only network. Setup stops before native or owning calls. The corrected topology retains internal module traffic and uses the existing second-network publishing pattern. | 69 / `805f07f0af9fba23dc74a2fb8e555ef370a4590214654db76943c47579526844` |
| `102924-674b13` / `943da8234ba` | Native before/after controls and eight examples pass. Two batch examples supply invalid comma-separated RHOSTS and fail option validation. Per-example capture counters also overwrite filenames, leaving incomplete packet evidence. Both harness issues are corrected before a full replay. | 105 / `6bb7f7ecd273ef5d9089ec92aa02ad0cb554ddd0654a7cee4992d014cc1cc7d0` |

The first setup's exact four containers/one network pass nine root queries.
The first owner run's four containers/two networks pass ten root queries. Both
leave global containers empty. The latter has genuine cold-console evidence;
the setup failure never reaches a console.

## Complete owning results

Run `20261111T103320-fe13d7`, source
`681c7cd5200386f9250a35e47771846ad3a8fcde`, passes **10 examples, zero failures,
pending or errors outside examples**, in **68.803244 RSpec seconds**. The manager
and root observer both terminate zero. Both native phases pass. The production
modules and the earlier TCP extractor lab remain unchanged.

The suite runs each module twice against each enabled release, twice against
disabled UDP and a closed port, and twice in two-host batches. Its twenty unique
call records contain 24 actual requests and 20 actual response datagrams. Sixteen
service and eight vulnerability API calls have the expected per-host UDP
arguments. Negative runs produce no service/vulnerability reports.

| Actual stats reply | Captured datagrams | Request/reply payload bytes | Verified printed proof |
| --- | ---: | ---: | --- |
| Legacy 1.4.39 | 1 | 15 / 1,314 | No packet amplification; 87x and 1,299 additional bytes |
| Modern 1.6.26 | 2 | 15 / 2,225–2,227 | 2x packets; 148x and 2,210–2,212 additional bytes |

Root independently rehashes all 38 selected inputs and rechecks twenty distinct
packet/module records, real request IDs, contiguous complete fragments, versions,
reply byte totals and printed calculations. The original parent contains 118
regular files. Root observes only the four bounded task containers, the actual
first prompt/isolated BOOT and two fresh metadata snapshots, with no first seed.
Ten exact-resource/label/global queries prove all four containers and both
networks absent afterward. There are no volumes, sessions, target files or cache
entries created by this profile.

The complete immutable 159-file source/run package has checksum-manifest SHA256
`ccd723d002aaf8b60d3426fb713a39dbd6387f74c3687e54d2a72e7bb4d5defb`.

## Review and remaining scope

- **Summary:** both scanners' ordinary IPv4 main paths pass on two genuine releases.
- **What looks good:** independent native protocol controls, per-call passive wire
  evidence, exact dynamic accounting, reporting arguments, repeats and batches.
- **Concerns:** no new code concern remains for this scope. IPv6, spoofed-source
  delivery, other releases and SQL reporting persistence remain unqualified.
- **Suggestions:** continue with other valuable compact targets; do not infer
  broader network support or persistence from these passing calls.

Five changed Ruby files pass syntax/RuboCop; module documentation lint, local
links and unchanged human Scenarios are checked. No full Framework suite is run.
