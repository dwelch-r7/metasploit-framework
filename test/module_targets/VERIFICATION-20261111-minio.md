# MinIO module qualification — 2026-11-11

The integrated checkpoint covers **184 runtime modules, 126 qualified lab profiles
and 1,429 functional examples**. This adds two MinIO profiles to the 124 qualified
manifest-backed families. The nine MinIO examples also exercise fourteen named
client states; those states are recorded separately and do not inflate the
example total. The wider campaign remains incomplete.

## Modules and genuine targets

- `auxiliary/gather/minio_bootstrap_verify_info_disc`
- `post/multi/gather/minio_client`

The [maintained lab](minio/README.md) owns the source compiler, image assembly,
Compose definitions, native controls and functional launcher. Both
[module](../../documentation/modules/auxiliary/gather/minio_bootstrap_verify_info_disc.md)
[documents](../../documentation/modules/post/multi/gather/minio_client.md) link
back to it. Its dedicated commands run separately from the generic manifest
launcher. `reviews.yml` exposes the standalone profiles to the static inventory;
registration alone does not establish a pass.

The server sources are pinned to affected
`RELEASE.2023-02-27T18-10-45Z` / `0ff931dc765d5d8fdddcdf7687fec1b0b194fca9`
and fixed `RELEASE.2023-03-20T20-16-18Z` /
`05444a0f6af8389b9bb85280fc31337c556d4300`.
The genuine client is `RELEASE.2023-03-20T17-17-53Z` /
`88896ae495128646081d8f809b8934c74cb90194`.
The public `build_sources.rb --build` completed in 627 seconds, with clean Git,
source checks, module verification, Go build information and exact binary hashes.
Its separate compiler was configured for one CPU and 1 GiB memory/swap. Recorded
`memory.peak` was 1,074,741,248 bytes, slightly above that configured value;
`oom` and `oom_kill` were zero. No below-limit peak is claimed for the compiler.
Runtime assembly uses COPY/metadata only, without RUN or compiler stages; no
BuildKit CPU/memory enforcement is claimed.

## Final observed results

Both invocations used frozen worker `47d49a132c4e3bf800da17307da0edf024d8ed4f`.

| Profile / invocation | RSpec | RSpec seconds | Actual result |
| --- | --- | --- | --- |
| Vulnerable `msf-minio-functional-20261111t025012-52db6b` | 6/0 | 584.703813 | Natural manager exit 0; native baseline, capture and teardown pass |
| Fixed `msf-minio-functional-20261111t030517-5146ca` | 3/0 | 70.330601 | Natural manager exit 0; native baseline, capture and teardown pass |

Both have zero pending examples and errors outside examples. Every cohort runs
genuine native controls before and after module execution: 69 CLI commands/six
HTTP requests per vulnerable check, and 63/six per fixed check. Actual versions,
UID/GID, live quorum, two online nodes, four distinct drive identities,
authentication refusals, repeated exact S3 object operations, bootstrap behavior
and logical restoration are checked. The four drives are logical storage paths,
not a physical durability or high-availability qualification.

The vulnerable API cases validate complete actual JSON loot, exact Untried/null
attempt SQL credentials with service origins, repeat/dedup and two-workspace
isolation. Four actual S3 cycles use credentials parsed from owner loot, twice
per node; every cycle restores its baseline. Four additional workspace-only
calls retain disclosure/JSON/SQL assertions and explicitly record S3 as not
executed, without cached success. Wrong-path refusals remain separate.

The client cases use one genuine Linux command shell and one Linux Meterpreter
session, with generated ELF bytes checked on target, typed session/PID/peer
identity, actual session writes and guarded process cleanup. All fourteen named
states enter, complete and restore successfully, with 22 actual owner calls:
default HOME, custom path with spaces, missing, empty, malformed JSON,
empty aliases and default after custom. Genuine mc creates both aliases; exact
rows, text loot, SQL host/workspace linkage, decoys, input bytes/UID/GID/mode and
absence restoration are checked. Native identity/proof checks surround each
state. Shell HOME is configured through an actual operator export and verified
by a separate command; absent-HOME behavior is not qualified.

The fixed cases make six real negative requests: four node refusals with HTTP
403/JWT-token-missing bodies and two wrong-path HTTP 400 responses. No credential records,
loot rows or new loot files are produced. Native S3/quorum remains healthy and restored.

## Resource and bootstrap verification

One project runs at a time. Native controls start three roles, then Framework
and PostgreSQL bring the maximum to **five containers / 1,600 MiB memory and swap
/ 2.35 CPUs**. Target nodes use 256 MiB/.5 CPU each, gateway 64 MiB/.2 CPU,
Framework 768 MiB/one CPU and PostgreSQL 256 MiB/.15 CPU. Each has pids limit 128.
Only the gateway publishes random loopback API ports; targets, database and
handler remain on the internal network. There are two networks and five owned
volumes. Both final cohorts have no OOM kills and recorded runtime memory peaks
below their individual configured limits.

The cached canonical Framework image is independently identified; each actual
cohort checks 251 installed dependency source files before console startup.
Parent live observations confirm the first real prompt, matching isolated BOOT,
no first-profile seed and two fresh parsed atomic metadata snapshots. After
natural completion, sixteen fresh queries per profile verify all five exact
container IDs, both networks, all five volumes, project labels and global
container absence. No images or unrelated volumes are pruned.

## Actual defect and retained failures

The original module passed a parsed Hash to `store_loot`, which wrote Ruby's
`=>` representation into an application/json file. Original invocation
`4f9e8f` preserved the genuine valid HTTP response, actual Untried SQL row and
1,256-byte invalid loot (SHA256
`47c67f43506f15f79aac1ae31839d556071c2d83253cef112415edc3059dc59b`).
It stopped after seven examples/one failure; six client cases had passed.
Native controls passed before and after. The separate one-line repair
serializes the full document using `json.to_json`; request/reporting behavior
is unchanged. Captured-response host stubs reproduce the original parse failure
and corrected full-document equality, independently of the final genuine runs.
The integrated repair commit is `48401e4a68d`.

The subsequent compact invocation `4816b9` hit the unchanged 600-second suite
bound. Eleven states completed/restored; malformed Meterpreter input reached
expected owner output but did not prove fixture restoration, and two states
were unreached. Its eighteen actual owner calls are distinct from seventeen
calls inside fully completed states. Partial RSpec JSON, its stop-time formatter
error and the secondary missing-summary error are retained. This is not a
passing profile or evidence of another owner defect. Removing only redundant
workspace S3 cycles allowed the final cohort to complete without extending the
bound. The 589-second final owner command is close to that bound; slower hosts
can still produce a setup timeout and must preserve that result.

Immutable evidence, independently byte-verified by the parent:

| Export | Entries | Manifest SHA256 |
| --- | --- | --- |
| `minio-public-source-build-20261111-2e9aca` | 192 | `984f1ac9d06a2ede4aa1ac7395bcaa8c8d999e2b7fd91e0217a1cbe217f5c96b` |
| `minio-functional-owner-json-failure-20261111-4f9e8f` | 632 | `6ebc815053e4bcf153b3ff571e9528cbf14a4528770ddcfb30e3f44d5e6b92ef` |
| `minio-compact-suite-timeout-20261111-4816b9` | 811 | `7bf9d0d26619efd2810aa5451f292ffc3e43f553f5da0e5e0e6c6d6c0ebc5775` |
| `minio-fast-runtime-assembly-20261111-3dc38f` | 304 | `54171dfcd13bafbc8a67ba69666224e1ad604e243a05b932d289b30f10daf50c` |
| `minio-fast-vulnerable-success-20261111-52db6b` | 841 | `eec59a4ea913400369a83d7d8758118ff443020991badff1e286b4ba5434938b` |
| `minio-fast-fixed-success-20261111-5146ca` | 439 | `243d6cda7bb69d301e1af4620aa9f478dff7c8ec9e0bf7144c8da7337f6b6d3c` |

Complete final invocations, including hidden/cache files, are copied into the
primary ignored `tmp/module-target-minio/runs/` directory: 557 and 171 files,
all byte-verified. Raw receipts and their original source maps are unchanged.

## Integration checks and remaining scope

The main branch matches 238 of 239 selected worker inputs. The sole difference
is newer, preserved `spec/support/acceptance/gogs.rb` code. Its helpers and Gogs
context are not included or invoked by MinIO. Guarded dry registration loads
both current Gogs and MinIO definitions and verifies six/three examples,
no Gogs methods in the MinIO group, and no Framework or target-process
execution in the discovery child.
This reviewed unused-helper difference is explicit; the old tested digest is
not rebound. All MinIO owners, lab code and other selected dependencies match.

Primary focused checks pass 57 native/build contracts plus 44 functional
contracts. Twelve new/changed Ruby files lint cleanly. The serializer module's
RuboCop/msftidy checks retain only the identical pre-existing duplicate-RPORT
warning at line 44. Module-document links are checked; human Scenarios are
unchanged. No full suite is run.

Windows shell, Windows Meterpreter, Windows PowerShell, macOS, other Unix,
other architectures/delivery modes and additional releases remain individually
pending. The inherited full CI result at `69f779414da` is 62 successes, one skip
and one failure: PHP 5.3/macOS Intel reports EAGAIN before UDP peer assertions.
A reproducible source framing defect is recorded separately in
[deferred investigations](DEFERRED.md); its exact relationship to that CI event
is unproven. No incompatible IO rewrite or CI retry is published by this change.
