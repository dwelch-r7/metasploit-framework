# Genuine Apache NiFi discovery targets

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/nifi_discovery/run.rb
```

Three serial profiles retain all fifteen cases for the version and login scanners against official
digest-pinned Linux amd64 NiFi 1.13.2, 1.21.0 and 1.22.0 images, with an ephemeral reporting database. The legacy profile also runs unrelated
Apache HTTP for product-refusal controls. The shared target components
live in `../nifi/`. No service response or authentication endpoint is simulated.

NiFi 1.13.2 uses its ordinary unauthenticated HTTP mode. The newer images use
self-signed HTTPS and their native single-user provider. `accounts.env` contains
public, artificial fixture credentials and a sensitive-properties key. Selected-release native
controls run before and after module calls and independently verify real UI script versions, API versions, accepted
and rejected authentication, authenticated identity and UID/Java. Flow component IDs and the properties-file hash must remain
unchanged. Both native
clients and modules use the configured NiFi hostname; module `VHOST` matches the
allowed proxy-host setting. Certificate verification is disabled for these local
self-signed fixtures; trusted-certificate behavior is not qualified here.

The missing application path really returns HTTP 200 with a branded "Did you
mean" HTML page and a browser meta-refresh. It contains no NiFi namespace script.
The tests require correct refusal rather than assuming a 404 or following a
browser refresh. Unrelated genuine Apache content is independently checked.

Ordinary cases repeat, including successful and rejected logins. Direct SQL
checks complete credential/service/origin/workspace graphs, exact account bytes,
SUCCESSFUL status and a validation timestamp. Repeated logins must not create
duplicates, and two workspaces remain isolated. The installed credential schema
has no persisted login-proof column; actual native responses and console output
remain external evidence. No such column is invented.

Targets use Docker's ordinary owned bridge, loopback-only random published
ports, init and an unprivileged NiFi user. No host network, socket, privileged
mode or host data mount is used. Ordinary Docker egress is not blocked. The guarded
runner records inputs/results/images and removes its own project and
volumes; initial native preparation and module failures are retained separately.

The `vulnerable`/`fixed` service labels refer to the H2 URL issue addressed in
1.22.0, not to a claim that either scanner exploits it. Processor execution and
credential gathering require their own functional qualification. This profile
does not qualify Windows, IPv6, LDAP/OIDC/client-certificate authentication,
other releases, every brute-force option or full TLS behavior. Existing human
module Scenarios are retained; this guide contains no invented console results.

The old `nifi_discovery` family now selects only the five legacy cases. Use the
launcher above for the full matrix:

| Family | NiFi release | Examples | Containers |
| --- | --- | ---: | ---: |
| `nifi_discovery` | 1.13.2 HTTP | 5 | 4 |
| `nifi_discovery_vulnerable` | 1.21.0 HTTPS | 6 | 3 |
| `nifi_discovery_fixed` | 1.22.0 HTTPS | 4 | 3 |

NiFi is capped at two CPUs, 1,536 MiB RAM/swap and 512 tasks. Framework uses
1.5 CPUs/768 MiB/256 tasks; PostgreSQL uses 0.2 CPU/128 MiB/64 tasks and bounded
tmpfs storage. Legacy Apache adds 0.2 CPU/128 MiB/128 tasks. Total caps are
2,560 MiB/3.9 CPUs/960 tasks for legacy and 2,432 MiB/3.7 CPUs/832 tasks for
HTTPS. OOM and PID-limit event counters must remain zero. Every role's complete
memory/PID counters are recorded before assertions. Memory-boundary crossings
are reported separately: the kernel can reclaim memory at that boundary, so
`memory.events:max` is distinct from an OOM event. See the
[kernel's cgroup memory documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files).
The runner removes image-declared anonymous volumes as part of project cleanup.

The original shared `nifi/discovery.py` remains unchanged for existing H2,
processor and credential-gathering profiles. The selected-release probe reuses
its version definitions and script parser, plus the existing native HTTP client;
it makes real target requests and does not substitute responses. Qualification
is recorded in dated verification reports after native replay.
