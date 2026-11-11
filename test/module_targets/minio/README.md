# Historical MinIO source/runtime component

This common component supplies genuine source-built MinIO and mc. It does not
register or qualify a Framework module family. Canonical bootstrap disclosure
and client-gathering corpora/module-doc links follow only after an independently
qualified topology. Existing module owners and human Scenarios are unchanged.

## Provenance and measured supply cost

`assets.json` owns source commits/tags, 15 file checks, official Go/Debian image
manifest/config/RootFS pins, resources, flags and measured local binary facts.
Sources are upstream `minio/minio` and `minio/mc`; no mirror binary is used.
The selected servers are RELEASE.2023-02-27T18-10-45Z and the advisory's fixed
RELEASE.2023-03-20T20-16-18Z. The client is RELEASE.2023-03-20T17-17-53Z.
These releases do not establish the disputed earliest affected boundary.

One actual source supply attempt passed in 676s on Go 1.19.13 linux/amd64 with
one compiler at 1024 MiB/1 CPU: mc 193s, vulnerable 246s, fixed 189s, plus 35s pull.
The compiler hit memory pressure: final configured max 1073741824, peak 1074511872,
max-events 25012, oom/oom_kill 0. Owned Go caches reached 3042952 KiB before their
writable layer was removed. Do not hide this cost in routine compose startup.

The exact reference outputs include ELF machine 62, full Go build info,
original vendor release flags, clean Git/source/module checks and SHA hashes.
These are locally compiled historical binaries, not publisher binary/signature
claims. Their full source archives and capture/down receipts are retained in
the campaign's immutable source-build evidence; only text metadata is used as
committed spec fixtures. No executable/opaque blob is committed.

The vendor advisory is [GHSA-6xvq-wj2x-3h3q](https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q).
The tagged release generators and Makefiles remain unchanged. mc's real
[ready command](https://github.com/minio/mc/blob/88896ae495128646081d8f809b8934c74cb90194/cmd/ready.go)
uses the genuine anonymous health API. Admin JSON field selection follows the
pinned client dependency's [InfoMessage/ServerProperties](https://github.com/minio/madmin-go/blob/4f013bfc73a4/info-commands.go).

## Explicit bounded source build

From the Framework root:

```sh
bundle exec ruby test/module_targets/minio/build_sources.rb --check
nice -n 10 bundle exec ruby test/module_targets/minio/build_sources.rb --build
```

The check mode reads files only. The build mode requires an empty global
container inventory and holds the same user-scoped lock as the guarded runner.
It refuses another owner's runtime. Do not run it alongside another lab.

The builder uses one official pinned linux/amd64 Go container, no host mounts,
HOME/secrets/socket or published ports, dropped capabilities, 1024 MiB/1 CPU,
swap 1024 MiB/pids 128. Its owned writable layer holds HOME/source/cache. Three
builds run serially with readonly modules/p1, GOMAXPROCS 1/GOGC 25/GOMEMLIMIT 768 MiB,
CGO_ENABLED 0 and the original release generators against exact clean Git tags.
The 1800s total, 600s pull and 900s component bounds do not grow on failure.

Before removal, logs/inspect/processes/cgroups/OOM and partial or completed
source/artifact provenance are captured. An expired build bound cannot suppress
independent bounded capture/down. A timeout before final checks cannot prove
post-timeout source cleanliness. Failed captures cannot skip teardown. All
exact owned container/network/volume IDs, project labels and global containers
are checked afterward. Images remain as cache; owned source/module caches do
not persist. No target server, Framework console or module is run by this step.

## Verify/import and runtime-only assembly

A successful compiler evidence directory contains result.json and artifacts/.
A captured build cannot be replaced by a downloaded guessed binary or a version
string. Import verifies every reference byte/hash, clean source checks, module
verification, platform/VCS/toolchain metadata and complete capture/cleanup.

```sh
bundle exec ruby test/module_targets/minio/assemble_images.rb --import /absolute/build/evidence
bundle exec ruby test/module_targets/minio/assemble_images.rb --verify-import /absolute/import.json
nice -n 10 bundle exec ruby test/module_targets/minio/assemble_images.rb --assemble /absolute/import.json
```

Import/verify are disk-only and never execute binaries or Docker. Outputs live
under ignored tmp/module-target-minio/imports/. Imported context copies receive
explicit executable modes; original sealed output stays unchanged. The campaign
can import its exact verified original source-build evidence instead of doing
another cold compile. Fresh users use the explicit bounded builder above.
Unexpected locally rebuilt hashes require investigation, not silent acceptance.

Assembly is a separate explicit operation, requiring an empty inventory and
the shared lock. A read-only `docker buildx inspect default` preflight without
bootstrap must establish the explicit default builder's built-in docker driver
before any assembly. Its single Docker context endpoint must report the same
engine ID as the current Docker engine. Ambiguous/unverified endpoints and other
drivers are refused; no builder is created, selected or reconfigured. Each build
pins the inspected endpoint with docker --context ENDPOINT buildx build and
--builder default per command, independently of mutable selected-builder
state. The global selection is neither changed nor used as a fallback. See Docker's
[driver/selection contract](https://docs.docker.com/build/builders/).
It pulls only the pinned Debian runtime, then uses one common
Dockerfile with COPY/metadata instructions and no RUN, apt, compiler, remote
frontend or external stage. It has a 180s total bound. BuildKit/daemon file-copy
CPU/memory enforcement is not claimed; no application/build-stage process runs.
Any unexpected persistent builder container appears in the final inventory and
fails conservation. Generated contexts contain only verified mc/server bytes,
provenance and empty UID 1000-owned home/drive directories. The assembled images
are local source-set identities, not floating vendor tags; native use requires
the exact assembly receipt and observed image IDs/RootFS/labels.

The initial import receipt SHA, verified descriptor and all source/context
digests are bound before execution. Equality is rechecked before each build,
after both builds, during capture and after cleanup. External conservation is
recorded alongside source conservation. A changed receipt/context cannot be
relabeled as the final import, and no successful assembly receipt is emitted.

No hidden auto-compile or image fallback is used by canonical startup. Future
module families require these explicit verified local images, with
pull_policy:never. Runtime binaries execute as numeric UID 1000, with no compiler
or OS-package installation in the runtime recipe.

## Independent two-node/four-drive native gate

After separate setup authorization, use:

```sh
bundle exec ruby test/module_targets/minio/native_gate.rb --check
nice -n 10 bundle exec ruby test/module_targets/minio/native_gate.rb --run /absolute/assembly.json vulnerable
```

The alternative fixed profile uses the same pinned source-built fixed server.
Each native invocation starts one project with two MinIO containers, each
256 MiB/.5 CPU, swap 256 MiB/pids 128, and one 64 MiB/.2 CPU gateway with
64 MiB swap/pids 128. All three run as numeric UID/GID 1000 with dropped
capabilities. The gateway alone publishes two loopback API listeners.
The same four literal endpoint URLs are passed to both genuine MinIO processes.
The four named drives are logical Docker storage paths, not distinct physical
failure domains or a high-availability/durability claim. Existing 120s readiness
and 180s native control bounds remain separate from capture/teardown.
The owned default network is internal and is the only network attached to either
MinIO server. A separate public network is attached only to the capped gateway.
Docker publishes ports through a default-gateway network, so an internal-only
server has no assigned host binding even when Compose accepts a loopback port
request. The gateway forwards each listener to one real node without changing
request paths or Host. It has no forward-proxy endpoint. Its read-only image and
configuration use only a small owned /tmp tmpfs. The existing campaign-pinned
httpd image must already be cached; the native gate never pulls or builds it.
See [Moby gateway behavior](https://github.com/moby/moby/discussions/53256).
This fixture change still needs actual gateway syntax/startup and native controls
under a separately granted runtime slot; disk contracts alone do not qualify it.

The real mc ready health command is bounded by healthcheck timeout/up-wait.
The pinned client's [anonymous-client construction](https://github.com/minio/mc/blob/88896ae495128646081d8f809b8934c74cb90194/cmd/client-admin.go#L151-L162)
requires an alias even for anonymous health. `MC_HOST_readiness` supplies the
loopback URL as a credential-free environment alias; the direct health command
uses `ready readiness` with its separate `/tmp/module-target-health` config. Native
authentication/S3 checks use their own aliases and configs. Before teardown,
read-only `id`/`stat` capture records the actual runtime user and configured drive
paths where exec remains available, including after readiness failure. Both
actual network inspect captures retain Internal/Options and endpoint details
before teardown. The native.py admin/auth/S3/disclosure/restoration assertions
and their direct internal mc routes remain unchanged.
Native facts require actual image/binary/source versions, UID/platform/cgroups,
no OOM kills, two online servers/four distinct drives and live quorum, stable
drive/deployment format metadata, actual S3 authentication and repeated small
put/stat/get/delete with exact bytes. Sample/cloud aliases are removed through
the real CLI before S3 operations, and only task-owned internal storage is used.
A separately rejected credential must return a real S3 auth error.

A separate raw HTTP client captures unauthenticated bootstrap bodies. On the
affected source it must prove real root credentials and a MINIO_-prefixed
sentinel, exclude a nonprefixed sentinel, then reuse those disclosed credentials
against real S3. The fixed source must retain working S3/quorum while refusing
unauthenticated bootstrap. No fake bootstrap route or management API is served.

Native-created objects/buckets/config/proof paths are explicitly removed.
Fresh absence/ownership guards, real CLI configuration initialization and
sample-alias removal run on both nodes before admin/S3 operations. mc creates
session/share/cert state with each command, so each node's complete owned
config tree and proof path are independently removed and absence-probed.
Cleanup attempts continue on the other node after a removal/probe error;
restored requires both nodes' absence proofs and logical restoration.
Logical bucket lists and stable drive/deployment/quorum metadata must match
their baseline; internal scanner/audit timestamps and counters are excluded.
No byte-identical entire-disk claim is made after real S3 activity. Every node's
logs/inspect/cgroups are captured before down-v; exact owned IDs, four volumes,
network, labels and global inventory must be absent. Failed setup/native
controls are not module failures.

No native topology or module qualification is claimed by disk checks or the
source supply gate. Bootstrap loot/UNTRIED SQL and client shell/Meterpreter
coverage remain pending. Windows shell/Meterpreter/PowerShell and macOS/other
Unix paths require individual genuine targets; Linux pwsh does not qualify
Windows PowerShell. Production fixes require captured original behavior first.
## Functional owner validation (candidate, not yet runtime qualified)

`functional_gate.rb` is separate from the source compiler, assembly and native
commands. It requires a genuine current assembly and a separately reviewed cached
canonical Framework image; it never builds or pulls a Framework image. Its CLI is:

```text
bundle exec ruby test/module_targets/minio/functional_gate.rb --check
bundle exec ruby test/module_targets/minio/functional_gate.rb --run ASSEMBLY_JSON vulnerable FRAMEWORK_REVIEW_JSON
bundle exec ruby test/module_targets/minio/functional_gate.rb --run ASSEMBLY_JSON fixed FRAMEWORK_REVIEW_JSON
```

Each runtime command requires its own explicit sole-slot grant. The review JSON
must identify operation `canonical_framework_image_review`, status `passed`, the
actual `engine_id`, immutable `image_id`, explicit local `image`, and
`context_sha256` exactly matching `Functional.framework_inputs`. These fields are
review evidence, not a replacement for an actual cached-image inspection. The
gate independently compares the real image ID/platform/engine before use.

The genuine original public `build_sources.rb --build` must pass before final
qualification. A retained prototype artifact or native success does not qualify
that wrapper. Changed selected inputs require a new explicit import and separate
no-RUN assembly; successful old receipts must not be rebound or synthesized.

The gate first runs the unchanged native controls on the two MinIO nodes and
gateway. Only after success does it add Framework and PostgreSQL on the internal
network. Five containers total are capped at 1600 MiB memory/swap and 2.35 CPU:
two 256 MiB/.5 CPU nodes, 64 MiB/.2 CPU gateway, 768 MiB/1 CPU Framework and
256 MiB/.15 CPU PostgreSQL. There are two owned networks and five named volumes.
Only the gateway publishes loopback API listeners; neither target, DB nor handler
has a direct host port. Native three-service limits/topology remain unchanged.

Logical module endpoints select gateway's captured internal-network address and
19001/19002. This component adapter preserves the common runner's one-network
guard. Startup uses `--no-build` and `pull_policy: never`. Actual image identity,
cgroups, HostConfig memory/swap/CPU/PID limits, processes, network Options and
cleanup are captured. The cached Framework dependency source check binds 251
Ruby/migration files from the exact pinned gems, in addition to the canonical
dependency build context and selected repository source closure.
Inside Framework, repository scripts use paths relative to the canonical image's
`APP_HOME`/`WORKDIR`, matching its read-only `/usr/src/metasploit-framework`
mount. Host repository paths are for host-side Ruby/Python/Compose operations.
Task artifacts deliberately retain the same absolute path inside Framework;
generated ELF, loot and isolated console config use that artifact mount.

The compact vulnerable plan has six RSpec examples: four API examples followed
by one genuine shell and one Meterpreter session. Each session exercises all
seven named client states with a fresh fixture and restoration for every state;
the 22 post-module calls and their assertions remain. Fixed has three examples.
Qualification results are recorded in campaign verification reports. The
bootstrap owner runs with raw HTTP
tracing, strict actual JSON loot, exact Untried/null-attempt SQL service-origin
credentials, fresh-workspace isolation, repeat/dedup and real S3 authenticated
using values recovered by that owner. Raw files (including unreported files),
SQL and console bytes are retained before assertions. Invalid JSON is a failure,
not permission to serialize it in the harness or change production code.
The two node-specific examples each execute genuine module-derived S3 twice.
The workspace-isolation example retains all four disclosure/JSON/SQL/dedup
calls without repeating those S3 cycles. Per-invocation `bootstrap-s3` records
contain either the actual executed proof/receipt or an explicit not-executed
workspace-only reason; skipped work never supplies a cached success.

Client cases use real Linux command-shell and Meterpreter sessions on node1,
actual generated ELF payloads/handlers and independently used sessions. Configs
come from the genuine pinned `mc alias import` CLI, covering all alias fields,
default HOME, a custom path with spaces, decoy selection, missing/empty/malformed/
aliases-empty inputs, repeat and CONFIG_PATH reset. Input bytes/UID/GID/mode and
initial absence are restored; the owner only reads files. Its text loot is
checked against every actual alias row; it currently creates no credential rows.
Session and loot host/workspace linkage is verified against genuine SQL records.
The invocation-local `client-states.json` ledger starts with 14 false completion
rows. Entered/completed/restored flags require successful actual preparation,
owner/session assertions and restoration. Unreached states remain visible; the
gate requires every exact state, all 22 owner calls and successful restoration.
Per-state fixture tokens and cumulative evidence counters keep captures distinct.
The RSpec command uses defined order to expose API failures before session setup.
Meterpreter retains its default supported raw ELF `PayloadLinuxMinKernel=2.6`,
explicitly pinned with no fork/prepend options. Shell payload exec clears its
environment: the genuine established shell records HOME-before, receives an
operator `export HOME`, and proves HOME in a separate subsequent command. This
qualifies the configured shell HOME path, not absent-HOME module behavior.
Ownership uses one atomically renamed pre-exec PID/starttime/UID/executable
record, actual session PID/peer/proof/ancestry, and native executable identity.
The transferred ELF's exact hash, UID/GID/mode/size are checked before launch.
Cleanup rechecks container and process identity before signaling; environment
tokens do not authorize ownership. All existing cases and resource bounds stay.
Runtime metadata snapshots use a fresh invocation-local `.metadata-cache/container`
destination and the unchanged shared driver's genuine BOOT/parsed atomic copies;
no cross-invocation seed or manual snapshot is supplied.

Windows shell/Meterpreter/PowerShell, macOS and other Unix paths remain individually
pending. Linux PowerShell cannot qualify Windows. Suite startup capacity is
unproven: 120-second readiness, 180-second initial native, 120-second auxiliary
readiness, 600-second fail-fast owner suite and 180-second final native controls
retain their individual bounds within a 1260-second operation. Final native
baseline must equal the initial cluster/deployment/four UUID/formats/bucket list.
Failure still captures and tears down exactly owned resources, with no retry or
next profile. No human-written module Scenarios have been changed.
