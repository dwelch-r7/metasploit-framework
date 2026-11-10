# Genuine Grafana SQL Expressions profiles

This corpus keeps the original fourteen functional assertions. Preparation and
native API command execution are separate from a successful Framework run.
Run only under an explicit serial resource grant.

| Family | Genuine target | Cases |
| --- | --- | --- |
| grafana_expression | Official 11.0.0 Ubuntu, signed DuckDB/shellfs, Viewer | 7 |
| grafana_expression_anonymous | Same 11.0.0, Anonymous Viewer, /observability/ | 3 |
| grafana_expression_fixed | Official 11.0.5+security-01 Ubuntu, same dependencies | 2 |
| grafana_expression_stock | Official 11.0.5 Ubuntu, absolute DuckDB binary absent | 2 |

Each profile has exactly one Grafana, ordinary Apache and canonical Framework:
three containers, one project, 1856 MiB / 2.5 CPU total. Only random loopback
ports are published. Linux amd64 is explicit and actual image/CLI/API platform
checks remain mandatory. Other projects must be down. No project gem, shared
SDK, runner timeout or production algorithm change is required.

The guarded sequential command, only after a grant for the entire invocation:

```sh
nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  grafana_expression grafana_expression_fixed grafana_expression_stock \
  grafana_expression_anonymous
```

The shared guard refuses a nonempty container inventory and holds its advisory
lock through all profile teardown. Normal metadata reuse is limited to this
single invocation. Do not inject a cache from another invocation.

## Version and runtime boundaries

Grafana 11.0.0 uses the vendor's Go fallback SQL tokenizer. Native API controls
on the actual pinned image produced both original-batch and FROM-tab-community
marker files as UID 472 after the service cache prerequisite was satisfied.
The original is still a copied owning-algorithm diagnostic: native API/host
observation is independent of Framework execution, not an independently designed
original exploit. Neither batch alone qualifies a Framework command or session.

Grafana 11.0.1 through the reviewed 11.0.5/11.1.0/11.2.0 sources use DuckDB's
SELECT-only SQL serialization. The preserved actual 11.0.5 baseline passed file
reads but rejected INSTALL/LOAD; four RCE examples failed. These are explicit,
unqualified RCE paths. An older successful target cannot establish success on
those releases. No production SQL algorithm change is justified by the legacy
native result.

The 11.0.5+security-01 fixed profile is an independent same-base security
comparison with the preserved affected 11.0.5 native/file-read evidence. It is
not described as the patched counterpart to 11.0.0. Both official 11.0.5 and
11.0.5+security-01 pins remain in assets.json. The stock 11.0.5 control proves
that /usr/local/bin/duckdb is absent; merely hiding it in PATH is insufficient.

The earlier official 11.0.6 native attempt reported a different binary commit
from the public tag and failed scalar SQL with a not-implemented serializer.
Its exact compiled cause is unresolved. Its raw attempt and input draft remain
separate; later success does not explain that failure. The initial arm64 archive
also remains an explicitly unexecuted research artifact.

Other releases/branches, operating systems, Enterprise/Cloud, authentication
proxies and payload delivery families remain unqualified. The current positive
paths are Unix Generic commands and real reverse_bash shells. No human Scenarios
are generated; the existing module documentation prefix is preserved.

## Genuine assets and service cache

Official Grafana Ubuntu images are digest-pinned. Actual health/CLI versions,
vendor RootFS prefix layers and vendor image labels are checked against the
recorded registry metadata. Tags alone are not evidence of running identity.

DuckDB v1.1.2 is fetched from the official release URL with the measured archive
SHA-256 in assets.json. Its ELF machine, binary hash and actual platform are
checked. The archive hash is not a publisher-signature claim; no binary blob is
committed. Only target unzip/libstdc++ packages are added.

Vendor run.sh exports HOME from GF_PATHS_HOME before starting Grafana. An earlier
attempt installed the CLI cache under /var/lib/grafana while the API attempted
/usr/share/grafana/.duckdb and received permission denied. That failure did not
establish either SQL algorithm's outcome. The current recipe creates/chowns only
the service-resolved .duckdb directory, installs the same signed extension bytes
there as UID 472, and aligns the independent CLI HOME with the actual service.
Vendor startup/security/parser files and application ownership are unchanged.
There is no .duckdbrc, extension preload or unsigned-loading bypass.

The gate captures actual PID 1 HOME/GF_PATHS_* and cwd, CLI context and ownership.
For the legacy positive profiles it also reads the genuine API's engine version,
home setting, signature policy, platform and installed/unloaded extension path
before either command diagnostic. CLI/service cache alignment is required; CLI
signed loading alone cannot establish API command execution. The fixed and
missing-binary profiles preserve their actual SQL refusals without inventing
API engine/cache equivalence.

## Native, functional and cleanup assertions

Native preflight records real CLI stdin/stdout/stderr and independent HTTP
requests/responses. It proves version, image/process identity, exact public file
bytes, Viewer role, valid/rejected/missing credentials, scalar/file behavior and
fixed/stock refusals. Configured Anonymous Viewer access is distinguished from
authentication of supplied invalid Basic credentials; protected /api/user must
still reject them. The precise go-duck CLI serialization input is retained as a
CLI compatibility control, not a claim that 11.0.0 uses that parser.

The copied A/B batch remains observational. A missing marker or algorithm error
does not suppress the unchanged fourteen Framework assertions once independent
setup passes. Failed artifact probing or restoration invalidates setup. Native
API proof requires exact API-only random marker bytes and UID, never HTTP 200
alone. Every native-owned marker is removed and its exact absence checked.

Generic runs use the public AllowNoCleanup option because they do not open a
session. The fixture records operator cleanup only after exact proof bytes.
Bash owning calls use public `run -z` to keep the console in its main dispatcher.
A separate generated reverse_bash payload, genuine multi/handler and native
UID 472 launch calibrate real command bytes, target PID/UID, explicit target
exit, native PID absence, host shell_close and console restoration before
owning cases. Calibration artifacts and port 4445 listener receipts are
separate from owning calls on port 4444. Calibration staging creates a new
mode-0600 file directly as UID 472 from the exact generated stdin bytes and
checks native owner/mode/SHA before Bash reads it. Privileged copy/chown is not
used; the preserved prior copy attempt failed permission checks before any
owning call and is not a module failure. Reverse shells must open, execute a
real service-owner command, repeat and let FileDropper remove registered output.
The same target-exit/PID-absence/host-close ordering is required for each owning
shell; a session row or ring is insufficient. Positive abort/error banners fail the
examples. Current-call output paths are collected in ensure even when the shared
helper raises; unexpected negative/session residue fails rather than being
silently removed. Proof files are separate fixture cleanup.

Logical accounts/datasources/dashboards and signed-cache hashes must equal their
baseline after native controls and after each example; authentication timestamps
are excluded. Sessions/jobs are closed, each owned project is captured/downed,
and exact container/network/volume and label absence must precede another cohort.

Primary references: [Grafana advisory](https://grafana.com/security/security-advisories/cve-2024-9264/),
[11.0.0 parser](https://github.com/grafana/grafana/blob/v11.0.0/pkg/expr/sql/parser.go),
[vendor HOME contract](https://github.com/grafana/grafana/blob/v11.0.0/packaging/docker/run.sh#L63),
[fixed backend](https://github.com/grafana/grafana/blob/9b8a50cc217809e995c6b6e4aa7f3a26f9755094/pkg/expr/sql/db.go),
[go-duck](https://github.com/scottlepp/go-duck/blob/v0.0.20/duck/duckdb.go),
[official DuckDB release](https://github.com/duckdb/duckdb/releases/tag/v1.1.2),
[shellfs registry](https://duckdb.org/community_extensions/extensions/shellfs).
