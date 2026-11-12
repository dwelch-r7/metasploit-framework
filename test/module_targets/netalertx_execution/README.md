# NetAlertX queued execution investigation

Use a current guarded result and verification report to establish functional
qualification. A container starting successfully is not sufficient.

This component runs the full, genuine NetAlertX backend, PHP/FPM, NGINX, cron and
s6-overlay from pinned Linux amd64 24.9.12 and 24.10.12 images. `vendor.json`
records actual application/cron source hashes. The qualified file-collection
fixture is reused only for its unchanged initial DB/config bootstrap and native
HTTP client; its files are not edited.

The vendor API's `savesettings` operation replaces the whole configuration.
Native calibration therefore submits a complete snapshot, changes only the
controlled plugin fields, and restores the exact original values. Discovery
plugins stay disabled. Native HTTP controls prove an unauthenticated harmless
command on 24.9.12, refusal on protected 24.10.12, and authenticated execution on
the control. Files contain the actual backend parent PID and have native ownership
proof. Settings/API state, actual backend identity, source hashes and cgroup
counters are inspected. The real cron restart path is awaited; it leaves two
backend processes through the shipped s6/cron interaction. Repeated native runs
must preserve the configuration and keep that process count bounded.

All runtime services use an **internal-only** Docker bridge. No port is published.
Native HTTP requests run in the target network namespace and preserve actual
statuses, headers, cookies and bytes. Framework sends real traffic directly to
the measured target address. This prevents accidental LAN access even if an
update resets discovery settings.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb netalertx_exec_24_9_12 netalertx_exec_24_10_12
```

The intended matrix covers repeated checks, refused AutoCheck without state
changes, Bash and default fetched Linux Meterpreter sessions, and CLEANUP enabled
or disabled. Public session RPC/file proof, SQL closure, native child termination,
fetch-file deletion and configuration comparisons precede recovery. Active settings, the real cron queue
and callback sockets must settle before the next run. Unexpected
configuration changes fail the example and are recorded before explicit native
recovery. A recovered test is not a passing test. Intentional restoration after
CLEANUP=false is recorded separately.

Only three containers run at a time: target **256 MiB / 0.4 CPU / 96 tasks**,
Framework **640 MiB / 1 CPU / 256 tasks**, PostgreSQL **128 MiB / 0.2 CPU /
64 tasks**. Memory/swap limits match. The vendor's s6-overlay owns PID 1; Docker's
additional init wrapper is disabled for this target. `/run` is temporary and
executable, as required by s6-overlay. `/tmp` is executable like the vendor's
ordinary writable filesystem; native calibration copies and runs a hashed vendor
ELF there before testing fetched payloads. Target state is temporary, and no persistent
or anonymous volume is needed. The shared bootstrap is a read-only bind mount.

This is separate from the qualified web-only file collection lab. Do not extend
that lab's qualification to execution, other releases, architectures, languages,
custom installations or background discovery features.

Sources:

- [Original research and remediation](https://rhinosecuritylabs.com/research/cve-2024-46506-rce-in-netalertx/)
- [Affected vendor source](https://github.com/netalertx/NetAlertX/tree/dcc43d1f3c6611cf1900c4d2d7aae0c5ec077ab4)
- [Control vendor source](https://github.com/netalertx/NetAlertX/tree/d36486ef6de3985dac19195cf333e4de31601bcb)
- [Vendor cron restart implementation](https://github.com/netalertx/NetAlertX/blob/dcc43d1f3c6611cf1900c4d2d7aae0c5ec077ab4/back/cron_script.sh)
- [Module guide](../../../documentation/modules/exploit/linux/http/netalertx_rce_cve_2024_46506.md)

The module must read a complete original configuration through the logs endpoint
before updating settings. Unavailable or potentially truncated snapshots are
refused before any write. API settings alone omit inactive plugin keys and are
insufficient for restoration. The vendor's generated header/comments may differ;
all original assignments are preserved. Older declared affected releases remain
unqualified: official 23.01.14 source lacks this logs endpoint and uses a different
settings-array format. A version-based check does not establish those prerequisites.
