# OPC-UA detection and complete framing — 13 November 2026

## Summary

Current input-matched checkpoint: **227 modules qualified in covered paths,
259 profiles and 2,431 functional examples**. The new OPC-UA lab passes all nine
cases and 20 public owning calls. A confirmed framing defect is repaired in an
isolated worktree, independently reviewed/imported and replayed against a genuine
server. The broader campaign remains incomplete. No PR is created.

## What looks good

Run the [lab](opcua/README.md):

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb opcua
```

The Dockerfile builds unchanged upstream open62541 **1.5.10**, commit
`93c3bdfc9ea4718b503c6cbf57876237addd0f2c`, from the SHA-256-pinned release
archive on the pinned Ubuntu 22.04 amd64 base. Source-available applications use
the public server configuration and client APIs; protocol responses and module
methods are not replaced. Compilation uses two jobs. SDK/base inputs are pinned;
Ubuntu build/runtime package versions are recorded in the image, rather than
locked to an immutable package snapshot.

Three server instances configure default buffers, 16 KiB buffers and an
insufficient 4 KiB buffer. The last returns the SDK's genuine ERR response,
`0x80020000` with a null reason. Transparent forwarders preserve actual bytes
while splitting the first ACK/ERR response byte or closing after the genuine
eight-byte ACK header. Python's unchanged standard-library SMTP server supplies
an unrelated-service control. These delivery faults are explicit test conditions.

| Cases | Owning calls | Expected result |
| --- | ---: | --- |
| Default ACK; custom-buffer ACK; native ERR | 6 | Exact native metadata and service rows |
| Fragmented ACK; fragmented ERR | 4 | Same complete native response and reporting |
| Truncated ACK; native SMTP; refused port | 6 | No OPC-UA detection or service row |
| Repeated switching between two real ports | 4 | Both endpoint records preserved |

Native controls run before and after the module. Six successful SDK client runs
discover real endpoints, open real sessions and read software version 1.5.10,
including through fragmentation. Two SDK clients reject truncation. Independent
raw clients read the complete ACK/ERR frames and verify byte equality through
the forwarders. This establishes the target separately from Framework's scanner.
The scanner creates no Framework session; its main function is detection and
service reporting.

An independent parent algorithm reconstructs all 20 owning captures from raw
TCP byte positions, requiring contiguous coverage and identical retransmissions.
Fourteen positive HEL/reply exchanges match native bytes exactly. Both truncated
responses contain only the declared 28-byte ACK's eight-byte header, SMTP replies
with its genuine banner, and both refused connections have captured TCP resets.
Proxy peer/port journals correlate the actual owning connections and preserved
upstream frames, including the deliberately separated delivery times.

Native SQL inspection confirms seven service rows across nine isolated
workspaces, with exact addresses, ports, protocol, name, open state and info.
Repeated scans preserve row identities without duplicates. All negative
workspaces remain empty. The SDK process identities/births, binary manifests,
package hashes and complete native handshake records remain unchanged afterward;
Framework sessions/jobs finish idle.

The source repair reads a complete bounded message within one existing
five-second receive budget. It checks declared lengths and ACK/ERR structure
before reporting, preserves the ignored Reserved byte and unknown status-code
fallback, accepts null/empty reasons, and ignores reasons over the protocol's
4096-byte limit. These rules follow the
[message header](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.2),
[ACK](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.4) and
[ERR](https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.5) definitions.
Expected network errors are handled only around the HEL exchange. Unexpected
parser/UI/reporting failures remain observable while socket cleanup runs.

Identical **45 owner regression cases** show 23 failures before and zero after.
Positive frames are actual captured SDK responses; segmentation, malformed
fields, clocks and transport errors are explicitly synthetic unit boundaries.
Seven separately loaded shared helpers also pass. Parent verification passes all
52 raw examples independently. Default RPORT 4840, an operator-selected port,
HEL layout, valid output, metadata and direct decoder return shapes are retained.
Syntax, strict RuboCop and module tidy pass with zero findings; documentation
tidy, Python syntax and catalog/config checks pass. Human Scenarios remain
byte-exact.

Final run `20261113T183150-414cb7`, revision
`178f911cdf21fd6caf0b86a843134818c7fc814a`, completes naturally in approximately
1 minute 58 seconds including startup. Controller, manager and observer exit 0;
their PIDs are absent. All 46 selected inputs remain byte-exact. The independent
observer verifies the first cold console and two fresh metadata files.

Three containers total **1,088 MiB RAM, 2.2 CPUs and 416 tasks**. Actual caps match
configuration, RAM/swap limits are equal, published ports bind only loopback,
and no container is privileged. All six cgroup queries have zero OOM/kill,
PID-limit and memory-limit events. All eight independent cleanup queries pass:
three exact containers and one network are absent, no volumes were created,
and global container inventory is empty. The guard exits 0, its PID is absent,
both advisory locks are free and no unrelated containers were removed during
its lease. Images and unrelated volumes are preserved.

## Concerns

The unchanged-owner baseline passes six cases and fails three in 17 public
calls. A single `get_once` reads only the first byte of fragmented ACK/ERR frames,
so both detections are missed. Conversely, the header-only truncated ACK is
printed as an accepted connection and persisted as a service. Exact native SDK
controls pass before/after, and packet/proxy/SQL correlation establishes all three
source failures. The entire run is sealed before any source edit; no case or
architecture is removed to produce the final result.

An initial standalone Compose build omitted the shared Framework overlay and
failed configuration before building a target. Its diagnostic is retained; the
corrected native-only build then passes genuine controls before any module call.
The separate baseline and source-fix receipts retain intermediate decoder/lint
attempts as well as the authoritative identical before/after suite.

This qualifies plain OPC-UA TCP with this SDK/configuration and IPv4 lab.
Other SDKs/products, release branches, IPv6, TLS-only transports and platforms
need individual review. It does not establish all behavior of licensed gateways.
The native C client/compiler and OS package manifests are recorded; this is not
a claim of a snapshot-locked or warning-free upstream toolchain build.

## Suggestions

Continue valuable feasible modules, including candidates without Docker hints.
Inventory is 5,179 source files, 229 registered sources, 276 pending documented
container hints and zero stale reviews. The four previously deferred profiles
remain unqualified; this change adds no hash-equivalence exemptions.

Local immutable receipts are read-only, single-linked and independently rehashed:

| Receipt | Entries / inputs | Manifest SHA-256 |
| --- | --- | --- |
| Native controls | 35 / 9 | `0f3585795ad192e5f5796bdc46ad41e86ac85f8e7307165d897c85e68079d276` |
| Full unchanged-owner baseline | 162 / 46 | `96376aab49a392b7e99fdbe8c189bf6250320c5113afc5919775cfc43707bbac` |
| Isolated fix `cb2f99436df` | 108 / 14 | `01a1f07ea332cb40cee89e6cb72388bf1bf821df2ff35a1b92dbe63fce15d9ab` |
| Final native replay | 185 / 46 | `1af92c9feafd6380d20d1e01f7ee612e10ab060f42e53aaf2a6c807e0df6425d` |

The final receipt is at
`/Users/dwelch/.codex/reports/opcua-framing-qualified-20261113`.
