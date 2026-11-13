# FreeSWITCH event-socket authentication lab

Run the profiles serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/freeswitch/run.rb
```

Qualification is recorded in dated verification reports. The pinned original
Drachtio image runs FreeSWITCH 1.10.10, commit 4cb05e7f4a, with its genuine
mod_event_socket and mod_commands. The image's six engine/module/client/entrypoint
hashes are checked before startup and after testing. Original source and vendor
build references are in vendor.json; these do not establish a reproducible
source-to-binary build match.

Normal event-socket and ACL configuration files expose only TCP 8021 on host
loopback. The lab explicitly sets conventional password ClueCon or a Unicode
password containing a space; it does not depend on the image's password default.
The restricted profile permits only container loopback. Its real local fs_cli
remains healthy while external clients receive the native ACL rejection. An
unrelated, genuinely authenticated OpenSSH target supplies a separate banner.
No responses, authentication or permission checks are simulated.

Each profile uses three containers: target, Framework and a disposable reporting
database. Application profiles cap memory at 1,664 MiB, CPU at 2.5 and tasks at
576. OpenSSH uses 1,024 MiB, 1.9 CPUs and 448 tasks. The image's declared log,
recording and sound volumes are replaced with bounded tmpfs mounts; there are
no persistent Docker volumes. Startup needs no network downloads or packages.
The original image may warn that real-time scheduler priority is unavailable;
no additional scheduling privileges are granted for these control tests.

Native controls verify full framed responses, wrong/correct authentication,
module loading, version and exact system-command output. Public module cases
cover check, explicit/default/password-file credentials, success ordering,
AutoCheck disabled, ACL/unrelated refusals and a refused TCP port. Owning paths
repeat twice. Passive raw capture in Framework's existing network namespace
records actual wire traffic; native clients do not replace Framework sockets.
PostgreSQL rows establish password-only credential identity and repeat behavior.
Configuration hashes, process identity, idle jobs/sessions and cgroup counters
are checked after testing. The companion execution module needs its own session
and delivery-family qualification; these login cases do not prove it works.
