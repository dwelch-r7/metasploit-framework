# Salt master verification — 12 November 2026

The checkpoint is **210 qualified modules, 192 profiles and 2,047 passing
functional examples**. The [Salt lab](saltstack_zeromq/README.md) adds three
profiles for `auxiliary/gather/saltstack_salt_root_key`. Registration of 212
sources is not qualification; 291 documented container hints and unhinted
candidates remain. Existing `druid_js`, `superset_rce_owner` and
`wordpress_admin` profiles remain excluded. No pull request is created.

## Targets and final results

Genuine Salt 3000.1 and 3000.2 masters run from official PyPI release archives
with verified SHA256 values. The official amd64 Python 3.7.17 base is pinned by
digest, and fifteen runtime wheel artifacts are locked by URL and hash.
Normal `salt-master` starts the service. No Salt source, transport response,
module method or reporting operation is replaced in functional tests.

The additional affected profile uses normal `publisher_acl` entries for the
local `bin`, `daemon` and `nobody` accounts. Its four-user key map requires a
long ZeroMQ frame. Native controls verify eight installed vendor files,
runtime packages, configuration and the real master process.

All final cases use source `eb7bee696b8ef9b3f425259fe054b297aa05c034`, run
`20261112T060032-84a589`.

| Target | Examples | Failures | Spec seconds | Seed |
| --- | ---: | ---: | ---: | ---: |
| Salt 3000.1, default master | 3 | 0 | 109.56 | 60219 |
| Salt 3000.2, fixed master | 3 | 0 | 65.27 | 37120 |
| Salt 3000.1, publisher ACL | 3 | 0 | 60.20 | 62087 |

All nine examples pass without pending examples or errors outside examples.
The original manager and observer coordinator exit zero. The first console has
an independently observed prompt, BOOT record and two fresh metadata snapshots;
later profiles use only the normal same-invocation seed.

Reproduce with:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb saltstack_3000_1 saltstack_3000_2 saltstack_3000_1_acl
```

## Confirmed defect and correction

The default affected master returns a 116-byte auth-info payload. With publisher
accounts, the genuine payload is 371 bytes. Salt's native client discloses the
correct root key and authenticates a real command, while the original module
prints `377 extra bytes after the deserialized object` and collects no key.
Its unconditional `res[4..]` removes the short-frame header and leaves part of
the long frame's length in the MessagePack input.

The corrected-harness original baseline, run `20261112T054644-1feec9` at
`79425bd5f20a9d4423974c02c3f7d4f8a18689c1`, has **three failures at the missing
key assertion**. Native before/after controls pass. The final ACL profile has
**three passes**. All 49 input names match, and only the production module and
ZeroMQ mixin hashes change. Vendor/runtime/configuration controls and target
filesystem layers match. Image IDs differ because the Compose project label
differs. Both runs use the same example identities and order; their actual
seeds differ, 27021 and 62087.

The fix adds a receiver for short and 64-bit lengths, multipart delimiters and
fragmented/coalesced TCP data, following [ZMTP framing](https://rfc.zeromq.org/spec/23/#framing).
Reads share a ten-second budget and are bounded to 1 MiB and sixteen frames.
The owning module consumes the decoded payload. Existing handshake, sender,
request serialization and companion RCE source remain unchanged.

Separate paired unit tests use identical files, all 33 example identities/order
and seed 45281. The owning module changes from **12 examples/six framing
failures to 12/zero**. The new receiver's 21 examples originally fail because
the API does not exist; all 21 pass afterward. Those API-absence failures are
not 21 additional production defects. Socket, handshake, output and persistence
are explicit unit doubles. Real initialization, serialization, unpacking,
`run`, credential arguments and CheckCode results execute.

An isolated owning-only run passes 12/zero and verifies the production stopwatch
require. The primary checkout passes **40 examples/zero failures**: the 33
focused examples plus seven automatically loaded datastore-formatting examples.

## Public behavior and independent proof

All **21 public `run` calls** cover default and explicit Dump actions, repeats,
hostname resolution, refused-port recovery and workspace isolation. Twelve
affected-target calls disclose the native-proven key. Six fixed-target calls
reject disclosure; three refused-port calls collect nothing. The closed port is
independently proved from the Framework console's socket API.

Actual SQL verifies **six credentials, six services and six vulnerability
records**, with correct host, port, module origin, credential type, service
association and CVE-2020-11651 reference. Repeats preserve their identities.
Credentials remain Untried with no authentication-attempt timestamp. The
Framework auxiliary runner persists the vulnerability from the returned
Vulnerable CheckCode. Loot rows and files remain empty.

The vulnerability retains the module's declared references; this lab does not
prove CVE-2020-11652 or qualify the companion exploit.

Before/after native controls make **24 genuine protocol requests**, including
six invalid-key rejections and six authenticated commands. A returned job ID is
insufficient: each accepted command must write its marker and have a matching
successful cached job result. Markers are removed. The fixed master denies the
unauthenticated method while retaining normal authenticated execution.
Reporting PostgreSQL accepts its fixture password and rejects a different one.
Its public schema is empty before Framework connects.

Vendor/configuration/package hashes, master key identity and process identity
remain stable within each run. Salt memory and PID event counters remain zero.

## Failed setup and assertion classification

Early native attempts exposed fixture mistakes: the client lacked `master_uri`,
the transport ping was incorrectly expected to return a boolean instead of its
echoed request, and `cmd.run` lost its `cmd` argument through Salt's reserved
runner keywords. Corrected native calls use `cmd.exec_code` and verify the actual
job result. No Framework module calls occurred in those failed preflights.

The initial full matrix also incorrectly expected no vulnerability record on a
successful auxiliary run. Source inspection and actual SQL establish automatic
CheckCode reporting; the corrected assertions verify that record. The separate
original ACL baseline then isolates the real production framing failure.
Original failures, intermediate unit-fixture corrections and actual exits are
preserved rather than replaced by the final success.

## Resources, evidence and review

Each profile uses three serial containers capped at **1,216 MiB/1.5 CPUs**:
Salt 320 MiB/0.3 CPU, reporting PostgreSQL 128 MiB/0.2 CPU and Framework
768 MiB/1 CPU. Only a random loopback ZeroMQ return port is published. Runtime
keys/cache/logs and reporting data use bounded tmpfs; there are no named or
anonymous data volumes, privileged containers or Docker socket mounts.

Every project is removed before the next. The final independent audit passes
**24 queries**, checking nine exact container IDs, three exact network IDs,
project-label inventories and the empty global container inventory. Both original
diagnostics also have terminal owners and successful independent teardown.

Immutable local evidence directories under `~/.codex/reports/` contain:

| Evidence | Entries / inputs | Manifest SHA256 |
| --- | --- | --- |
| `saltstack-original-diagnostic-20261112` | 354 / 52 | `849ab8427ac10c3f183044d26f2dafc5cd929411a2ae70211fe2040630a909c1` |
| `saltstack-acl-original-baseline-20261112` | 258 / 49 | `455caa5e28fb22a0457eacc33b0c91d8ca477745f871fd1fd80e8757ab0d5fe5` |
| `saltstack-verified-20261112` | 480 / 53 | `f4d7f568565b41dd8413f7b275f9bd27c897c3b6b0ae31de4f38523b438b5085` |

The separate worker unit seal has 91 entries plus its JSON manifest, SHA256
`2fde9429a78885ea04752f3d503083e49134132972577117c2758ceb07952294`.
The parent verifies and copies it independently, including exact matches for
eight genuine native captures. Manifest entries use separate single-link files.

Strict RuboCop has exactly the same three pre-existing library documentation/
blank-line findings before and after; the module and new specs are clean.
MSFtidy and syntax pass. Module-doc lint retains its existing informational
missing-Options note; human Scenarios remain byte-identical. No full suite runs.

**Summary:** Genuine master collection passes, including the reproduced long
response regression and actual reporting.

**What looks good:** Independent native behavior, source identity, public calls,
SQL, repeats, state preservation and exact cleanup agree.

**Concerns:** Salt 2019.x, TLS/IPv6, other deployment products, command/heartbeat
frames and larger messages remain unqualified. Native authenticated execution
does not qualify the exploit's four master/minion payload targets.

**Suggestions:** Continue genuine minion and exploit/session coverage in the same
serial resource budget, retaining independent prerequisites and failure causes.
