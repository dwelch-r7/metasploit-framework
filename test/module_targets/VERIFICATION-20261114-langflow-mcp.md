# Langflow MCP collection qualification — 2026-11-14

All **nine functional examples and eighteen public module calls pass**, with
four complete JSON loot comparisons and matching database records. No owning
module source defect was found in these configurations. The campaign reaches
**233 modules qualified in covered paths, 276 profiles and 2,639 functional
examples**. The broader goal remains incomplete. No PR is created.

## Reproduce

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow langflow_empty langflow_auth
```

| Profile | Genuine configuration | Examples/calls | JSON loot |
| --- | --- | --- | ---: |
| `langflow` | Auto-login on; two private owned flows | 3 / 6 | 2 |
| `langflow_empty` | Auto-login on; no owned flows | 3 / 6 | 2 |
| `langflow_auth` | Auto-login off; authenticated native control works | 3 / 6 | 0 |

The [lab guide](langflow/README.md) and [vendor record](langflow/vendor.json)
describe the pinned Linux amd64 image. Installed versions are Langflow 1.8.4,
langflow-base 0.8.4, lfx 0.3.4, MCP SDK 1.26.0 and Python 3.12.12. The process
runs as UID 1000/GID 0. Three installed authentication/MCP source files match
their upstream release-tag bytes. The app, database and protocol are genuine;
no replacement endpoint or external AI provider is used.

Run `20261114T030026-53c482` completes in approximately **3 minutes 37 seconds**,
including a cold console, three serial targets, native controls and teardown.
Both the manager and independent observer exit **0**. The observer waits for
Compose preflight, checks live resource settings and validates the actual first
cold BOOT/prompt and fresh metadata; subsequent profiles use only the normal
same-invocation metadata seed.

## What the tests establish

With auto-login enabled and `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=false`, ordinary
anonymous REST flow requests receive 403. A credential-less MCP client can
nevertheless initialize the global SSE session and obtain owned private-flow
metadata. The two canaries are created through the authenticated application
API, with `access_type=PRIVATE` and `mcp_enabled=false`. Their descriptions
include Unicode and more than 4,096 bytes. The global listing exposes them in
this version; the tests do not change the target's authorization implementation.

The default auto-login startup also creates 32 unowned starter flows. Those are
real application data and do not appear in the MCP tool list. Native calibration
established this rather than assuming that a fresh database has no flows. With
auto-login disabled, anonymous auto-login and SSE requests receive 403, while
a valid configured-user login permits the same native MCP operations. This
distinguishes authorization enforcement from a broken service.

The independent client uses the vendor SDK's public request API to request the
same `2025-06-18` protocol version as the owner. Its initialization, capabilities,
server identity, tool schemas and descriptions match the complete saved JSON.
Tool order is normalized for comparison; every field and string is retained.
The database must contain the corresponding path, loot type, content type,
filename and target host. Two normal `run` commands on the same selected owner
produce fresh real MCP session IDs and separate loot files. No second `use`
occurs between those calls. Missing paths and native-proven refused ports are
also repeated, without creating loot or reports.

Native before/after results match in all profiles. Cleanup removes only the
API-created canary flows and verifies the original flow ID set. Installed
package/source identity and the protected/exposed behavior remain intact.
All nine native probe invocations exit zero; no Framework sessions or jobs
remain after any module call.

## Resources and verification

Three containers run at a time: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and PostgreSQL 128 MiB/0.2 CPU. Swap equals the memory cap,
privileged mode is disabled and published ports bind to localhost. OOM,
OOM-kill and PID-limit counters remain zero. No application volume is created.
All **24 independent final cleanup queries** pass for the nine container IDs,
three networks, project labels and global inventories. Five subsequent Docker
inventories are empty, and the shared heavy-lane lock is free.

Strict Ruby lint reports zero offenses for the new spec/helper. Python syntax,
filtered discovery (seven shared content examples) and module documentation
tidy pass. No full RSpec suite was run. The owner source is unchanged, SHA-256
`aeeb9f31cd8ac71414feb981546fa897cb1bdce3e556b3f2d8294c6cec0ed622`.
The original module guide's `## Scenarios` through EOF remains byte-for-byte
identical, SHA-256
`7ff459eba85d68db450bd0b56cdaf891500474444fac8d393fe302e52819dde2`.

The fixture commit is `79575895aaa6de7422653109c88e3546fc8420af`; its 42 selected input
hashes match the genuine completed run.

## Evidence and calibrated failures

The immutable archive
`/Users/dwelch/.codex/reports/langflow-mcp-qualified-20261114` contains
**262 files and 42 selected inputs**, copied without hardlinks and independently
hash-verified. Its `MANIFEST.sha256` hash is
`a2f287c55467d9db8194fe78e24c05d4becb906f96cbd3afc74df4db860e2e2a`.

Earlier native successes are separately sealed: empty tools, populated private
tools, authenticated service operation, and explicit protocol negotiation.
The protocol-aligned archive is
`langflow-native-protocol-aligned-qualified-20261114`, manifest
`6d62f4f5e453ff196b3fb1120ec86fa40e9edcd8a7d57ccf67bb533128bc1628`.

Two earlier probe failures are preserved as harness/oracle failures, with no
owning module calls: the initial HTTP reader omitted gzip decoding and assumed
an empty flow registry; a later helper-local import shadowed `urllib` before
its first application request. Both were corrected and all resources were
independently audited absent before continuing. Their archive manifests are
`d1db179d609072425d1dea831f75575445c5048db1f0bbdc68c6ea94eaf5d365`
and `b6580e295fbfd2f0a5b33557a21147807eadf92d26495c1db1b19833becc6e3d`.
These are not classified as module failures.

## Self-review and remaining scope

**Summary:** The gathering owner's real collection, persistence, repeat-run
behavior and expected refusals qualify in the three covered deployments.

**What looks good:** Native SDK/API controls, privately owned canaries, complete
Unicode/long-description comparisons, database persistence, untouched Scenarios,
bounded resources and exact teardown audits.

**Concerns:** Other versions, architectures, TLS and URL prefixes remain
unverified. The twelve related Langflow RCE owners are not covered by this
gathering result. No additional material finding remains in the tested scope.
The [vendor advisory](https://www.ibm.com/support/pages/node/7294467) covers a
broader affected range; this checkpoint does not infer that range from 1.8.4.

**Suggestions:** Reuse the genuine backend for the related owners after
calibrating each execution path and prerequisite. Current inventory: 5,179
source files, 235 registered owners, 270 pending documented container hints and
zero stale reviews. Previously recorded `druid_js`, `freeswitch_batch`,
`superset_rce_owner` and `wordpress_admin` deferrals remain unchanged. The older
remote Mettle `post/test/file` timeout still has an unverified cause.
