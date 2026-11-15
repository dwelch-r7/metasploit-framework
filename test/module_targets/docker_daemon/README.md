# Docker daemon functional targets

These eight profiles exercise `exploit/linux/http/docker_daemon_tcp` against genuine Docker Engines 26.1.4/28.0.4, Debian cron, a local Distribution registry and nginx gateways. All 43 cases pass in the [recorded qualification](../VERIFICATION-20261115-docker-daemon.md): 28 used/closed root sessions and four exact finite UTF-8 command proofs. Image-tag and blank-name fixes have genuine passing replays; finite execution retains its explicit operator-cleanup contract.

## Run one profile

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb docker_daemon
```

Use the same command with each family below, one at a time. The shared guard refuses existing containers, serializes worktrees and requires teardown before the next family. Each profile has a fresh target, Framework configuration and reporting database.

| Family | Cases | Scope | Current evidence |
| --- | ---: | --- | --- |
| `docker_daemon` | 11 | Direct/proxied detection, denied/refused endpoints, repeated Linux/Python Meterpreter sessions | Final shared-default replay passed |
| `docker_daemon_28` | 11 | The same full check/session paths on exact Engine 28.0.4 | Recorded pass |
| `docker_daemon_shells` | 2 | Repeated Linux/Python command shell sessions | Recorded pass |
| `docker_daemon_auth` | 6 | HTTP/TLS missing or rejected credentials, ForceExploit and disabled AutoCheck | Recorded pass after separately retained harness corrections |
| `docker_daemon_gateways` | 3 | Repeated sessions through nginx, HTTP Basic authentication and authenticated TLS | Recorded pass |
| `docker_daemon_registry` | 4 | Genuine registry pulls, cache reuse, missing tag and `3.2` versus cached `3.20` | Fixed replay passed |
| `docker_daemon_names` | 3 | Reusable name, stopped-name collision preservation and blank optional name | Fixed replay passed |
| `docker_daemon_finite` | 3 | Default cleanup guard and explicit manual-cleanup Linux/Python finite commands | Recorded pass; operator cleanup is explicit |

## Target and resource boundaries

Three outer containers run: the privileged target (1 CPU, 1 GiB, 256 PIDs), Framework (1 CPU, 768 MiB) and reporting database (0.5 CPU, 256 MiB). At most one short-lived inner Docker workload runs at a time, for at most four running containers. No host port is published. The target has no host filesystem or host Docker socket mount; Framework receives the repository's normal read-only source mount.

The target's own daemon hosts the inner workload. Its root bind therefore writes into the disposable target. Native controls independently established this namespace using a target-only anchor, actual root-owned bytes and normal Debian cron. This profile tests the remote daemon owner; it does not qualify kernel or shared-runtime escape modules.

`/var/lib/docker` uses a bounded 512 MiB tmpfs with `exec`. The default `noexec` tmpfs was independently reproduced as the cause of a native runc permission failure, before any owner invocation. It must permit execution for genuine inner workloads.

The Engine image defaults to a pinned 26.1.4 digest in the shared Dockerfile; the 28 profile supplies its pinned image through the same build argument. Registry, Alpine root filesystem and Debian base images are also digest-pinned. Debian APT packages remain release-repository inputs; the build records their installed versions in `/opt/module-target-packages.txt`. Do not describe all transitive packages as immutable. Target image IDs and selected source hashes are retained in each run.

## Controls and observable results

Native controls establish real API/root-write behavior, registry push/pull and Debian cron before module classification. Per-run controls compare daemon CLI/HTTP versions and actual gateway JSON, verify TLS with the generated lab CA certificate, and establish HTTP 401 for missing/rejected credentials. Public lab credentials are `module-target-user` / `module-target-password`. Framework retains its normal HTTP-client TLS policy; native certificate verification does not imply that Framework verifies the self-signed certificate.

Session cases use the actual loaded owner and public session APIs. Native target reads check exact marker bytes, UID 0 and process identity. Remote exit, closed database records, idle jobs/sessions and source-created cron/payload removal are checked before test cleanup. The Python command-shell payload launches a child per command; its persistent Python parent is observed and remotely terminated rather than mistaking child exit for payload exit.

The registry profile removes the exact tag after a successful independent pull, so the owner must pull it itself before the second execution exercises cache reuse. Naming controls preserve a real preexisting stopped container and separately prove that an unnamed container works when addressed by Docker's returned ID.

Finite commands explicitly require `AllowNoCleanup=true`. Their retained cron/payload files are recorded before controlled operator cleanup; those cases must not be reported as owner automatic-cleanup success. The normal cleanup guard is tested separately.

## Evidence and cleanup

The runner writes command logs, actual HTTP observations, native reads, session/SQL records, image/container inspection, selected-input SHA-256 values and RSpec results under `tmp/module-target-tests/<run>/<family>/`. Focused source-contract specs use explicit HTTP/payload doubles and are separate from genuine target qualification.

The runner captures evidence and runs Compose `down --volumes --remove-orphans` on failure as well as success. Parent audits independently verify project container/network/volume removal, global container absence and lock release. Source-owned effects are identified from successful create responses and pre-dispatch path snapshots; cleanup never guesses ownership from a random-looking name. Core daemon/cron/registry/nginx identities and cgroup OOM/PID-limit events are checked.

Normal cron scheduling accounts for most session time. Each payload execution has a bounded wait; no source clock or cron implementation is simulated. Other daemon versions, rootless/user-namespace variants and Docker mTLS remain separate qualification work. Both Engine 26.1.4 and 28.0.4 have separate native controls and real owner-session evidence.
