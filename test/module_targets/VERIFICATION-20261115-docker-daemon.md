# Docker daemon functional qualification

This checkpoint concerns `exploit/linux/http/docker_daemon_tcp`. It is not a whole-campaign replay or completion claim. The eight retained profiles pass 43 distinct cases and 83 public module calls, including 28 used/closed root sessions and four exact finite UTF-8 command proofs. Recorded cumulative qualification advances to **248 modules in covered paths, 327 profiles and 3,068 functional cases**. Older families retain their own inputs and scope.

## Recorded results

| Profile | Cases | Recorded result | Genuine sessions |
| --- | ---: | --- | ---: |
| `docker_daemon` | 11 | Final shared-default recipe/helper replay passed on current source | 4 |
| `docker_daemon_shells` | 2 | Pass on recorded inputs | 4 |
| `docker_daemon_auth` | 6 | Pass after retained harness corrections; 12 denied public executions | 0 |
| `docker_daemon_gateways` | 3 | Pass on recorded inputs | 6 |
| `docker_daemon_registry` | 4 | Fixed replay passed, including exact version-tag boundary | 6 |
| `docker_daemon_names` | 3 | Fixed replay passed, including blank optional name and collision preservation | 4 |
| `docker_daemon_finite` | 3 | Pass: default guard plus four real finite UTF-8 byte proofs, with explicit operator cleanup | 0 |
| `docker_daemon_28` | 11 | Native controls and full owner suite passed | 4 |

The shell, authentication and gateway profiles retain their earlier frozen source/helper snapshots; default-26, registry, naming, finite and Engine-28 runs use final source. The registry replay uses final owner SHA-256 `9c7457976af6256c9891bf45845d2c097d923feef8bb9658f27636a99e0b5f21`; its four cases have no failures, pending cases or outside errors. Its six sessions were used as root, exited remotely and closed in the database. Actual target reads verified exact markers and source artifact absence before harness cleanup. All three image references were pulled once and reused on their second execution. The nonexistent tag was rejected without container creation.

## Confirmed owner defects and focused repairs

The original passive check reported `Vulnerable` from a Docker banner/listing, returned false `Safe` through genuine nginx gateways, and treated denied access as `Safe`. The corrected check corroborates collection/version JSON, returns reason-bearing `Appears` for passive access and `Unknown` for unavailable, denied or malformed probes. Proper AutoCheck integration replaces the original exact-`Vulnerable` manual gate. Genuine detection changed from nine cases/eight failures to nine/zero before session qualification.

The image-cache helper originally searched the entire image-listing body for a substring. With only `:3.20` cached, it incorrectly accepted a request for `:3.2`, skipped the real registry pull and received Docker's `404 No such image` during creation. An independent native pull of the requested tag had already succeeded. The repair asks Docker's image-inspect API to resolve the original reference. The unchanged four-case registry suite changed from one failure to zero, including six real sessions in the fixed replay.

With `CONTAINER_ID=''`, Docker successfully created a container and returned its ID. The owner ignored that ID and sent ID-less `/containers/start` and `/containers/wait` requests, both genuine HTTP 404. An independent unnamed-container control successfully started, waited, wrote root-owned bytes and removed the container using the returned ID. The repair validates and uses the returned identity for start, wait and deletion while preserving the name option and collision behavior. Its unchanged three-case fixed replay passed with four used/closed root sessions; both blank-name executions used returned IDs, and the preexisting collision inspection remained unchanged.

Source changes are separate topic commits: `a81160e62e9`, `95f4c60d527` and `f6c0e63fdd6`. No PR has been created.

## Focused unit evidence and limits

With identical final source-contract spec and seed `2375`, the original source has 103 examples/47 failures, the cache-only predecessor has 103/21, and both repairs have 103/zero. The 103 examples comprise 96 owner examples and seven automatically loaded `Acceptance::DatastoreFormatting` support examples. All 82 predecessor descriptions remain, including the earlier 56 (49 owner plus seven support examples).

HTTP and payload boundaries are explicit doubles. Real Rex parsing, AutoCheck, request serialization and unchanged inert delivery constructors execute; these unit results do not prove native image resolution or exploitation. Other reference forms and malformed successful-create IDs have synthetic coverage and retain that qualification limit.

Strict spec lint passes. Strict owner lint retains ten baseline findings and exits 1; no new findings or suppressions were introduced. `msftidy` exits 0 and skips integrated RuboCop for this legacy module. Syntax and diff checks pass. The edited guide passes `msftidy_docs`; its human-written Scenarios-through-EOF suffix remains byte-identical, SHA-256 `6d4c367f8309f56b6ce31a146f1b6c771cc8431bc58c9e21c01bcd7ee6d9b82f`.

## Fixture validation and retained failures

The target combines genuine pinned Engine 26.1.4 binaries, Debian cron, Distribution 2.8.3 and nginx. Native controls established actual create/start/wait/delete, target-root bind writes, ordinary cron execution, real registry push/pull, HTTP Basic barriers and verified TLS before owner classification. Debian package repositories remain mutable release inputs; do not claim fully immutable transitive builds.

A native launch first failed with `Permission denied` on the Docker data tmpfs. An isolated identical-file probe independently established `noexec` as the cause; explicit `exec` permits genuine workloads. This was a fixture failure before owner execution. Two authentication-test drafts also stopped before owner HTTP calls: an unqualified test constant, then Framework's normal FileDropper guard after the harness disabled its handler. Their original evidence was retained before correction. They are not module defects.

Direct-daemon start/delete calls can yield nil at the Framework response boundary despite independently confirmed successful effects; proxied HTTP 204 responses parse normally. The targeted repairs preserve that behavior. A retained native runc cleanup warning has no established initiating cause. Neither observation is relabelled as repaired by the two source changes.

## Resource and cleanup contract

Run one family at a time with `DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb FAMILY`. The [shared target documentation](docker_daemon/README.md) contains recipes, individual profile commands and boundaries.

Three outer services are bounded: target 1 CPU/1 GiB/256 PIDs, Framework 1 CPU/768 MiB, PostgreSQL 0.5 CPU/256 MiB. Only one short-lived inner workload runs at a time. No target host port or host Docker socket/filesystem is mounted. The target's own root filesystem is the daemon-host root under test. This does not qualify kernel or shared-runtime escape owners.

Each batch records selected-input hashes, native commands, actual owner observations, session/SQL receipts, resource events and owned teardown. Source cleanup is verified before test cleanup. Cleanup ownership comes from successful create responses and pre-dispatch snapshots, never a guessed random-looking name. Independent parent queries verify project container/network/volume absence, global container absence and released lock before the next stack starts. Passing registry replay has eleven matching core-process snapshots and no OOM/PID-limit events.

## Qualification limits and continuation

Naming and finite profiles are complete and sealed. The finite profile proves default refusal, four root-owned UTF-8 markers, process exit and zero sessions. Its eight residual source files were recorded before explicit operator cleanup and absent afterwards. Engine 28 native prerequisites passed with actual root bind/cron bytes, registry pulls and three gateway root-write controls; its eleven-case owner suite passed with 22 public calls, twelve Appears and ten Unknown results, four used/closed root sessions, unchanged core processes and no OOM/PID events. The final default-26 replay also passes all eleven cases with the version override unset, verifying the shared recipe/helper defaults and current source without increasing the distinct case count. Finite artifacts must be recorded before explicit operator cleanup and must not count as automatic owner cleanup. Other versions, rootless/user-namespace variants and Docker mTLS remain separately unqualified.

The final evidence index and additive ledger retain one selected passing run per profile. The older base replay and six sessions from failing registry/naming discovery batches are excluded from qualified totals. The broader source inventory still contains thousands of unreviewed module candidates; registration or container hints alone do not establish passing coverage or infeasibility.

## Selected immutable evidence

| Profile | Run | Cases / public calls / sessions | SHA-256 manifest |
| --- | --- | --- | --- |
| `docker_daemon` | `20261115T114653-180a98` | 11 / 22 / 4 | `ec620b1afd592c13fa0050e2dd65307bd4e3ea654499c017b26632f350a27bb8` |
| `docker_daemon_shells` | `20261114T211129-f5a797` | 2 / 4 / 4 | `fdf90fa79872704386a2f4167127d5bf9a426c22d4d9f4b5b535860908051c6e` |
| `docker_daemon_auth` | `20261114T212221-a10852` | 6 / 12 / 0 | `e590ad81be88d4932157dd92de614eb7292215784a88198dddb4ccdb929c2b40` |
| `docker_daemon_gateways` | `20261114T212559-d68e47` | 3 / 6 / 6 | `249a60d2890ff2c688f5257f101553f5ef93dab8179ec7124b0dae20217b3bfa` |
| `docker_daemon_registry` | `20261114T220940-ac5516` | 4 / 7 / 6 | `e0bf3d50ea70a739329c4ee8d13153dc1ab9431580804eb6b0ce3a5178fc2f20` |
| `docker_daemon_names` | `20261115T112013-3e852c` | 3 / 5 / 4 | `033043b3d094e41be5057f6dbbfcf6ac8ab9783bd252ee53eec5524d42a802bc` |
| `docker_daemon_finite` | `20261115T112703-1dbed9` | 3 / 5 / 0 | `e655da4579724980a61021f836a57cb05bd616cb274a264f825c2067ce9ea1c2` |
| `docker_daemon_28` | `20261115T113736-f13121` | 11 / 22 / 4 | `62d993da2e1c6723941a094f1b181a3e585ecb4458d59dcb87a505baf8d07320` |

The manifests and raw logs are preserved under the corresponding `docker-daemon-*` directories in `/Users/dwelch/.codex/reports/`. The selected eight runs pass 40 independent parent Docker queries plus eight lock-release checks. Native prerequisite and predecessor-failure archives remain separate. The final audit rehashes sixteen passing/failing/source/native archives (1,500 files). A supplemental audit checks the exact 24 outer container IDs and eight network IDs from all selected runs; every original resource is absent, with no image volumes created.

The focused 103-example comparison starts from source `2af5c089…` with the earlier detection fix already applied. Its cache-only predecessor is `d643b959…`; final source is `9c745797…`. The original pre-detection source `597c8930…` has a separate 56-example comparison (44 failures to zero). Neither unit series is a native execution count.

No production library, payload, external dependency or unrelated module is changed. The human Scenarios suffix is preserved; new verification instructions and the reusable lab link are placed before it. Fork publication and hosted CI results are reported separately from local qualification; hosted acceptance checkouts must be inspected before claiming they exercised the trigger branch. No PR is created.
