# WordPress File Manager container qualification, 2026-11-16

One owner gains six profiles and 36 functional cases, reaching **260 runtime
owners in recorded covered paths, 407 profiles and 3,427 functional cases**.
All 72 public calls meet their success/refusal contracts. Eight native and
sixteen owning sessions are used and closed remotely. The module removes all
sixteen owning session files before operator recovery. Twelve command-only
proofs succeed as UID 33, with explicit operator file recovery.

This qualifies the [File Manager owner](../../modules/exploits/multi/http/wp_file_manager_rce.rb)
in the paths below. Earlier campaign evidence stays historical; this is not a
replay of every owner against the current harness. Registration alone does not
establish a passing module. The broader campaign remains open. No PR is created.

## Current functional results

| Profile | Genuine target/control | Cases | Public calls | Native/owner sessions |
| --- | --- | ---: | ---: | ---: |
| `file_manager` | 6.0, root installation, both commands and selected PHP families | 11 | 22 | 6 / 12 |
| `file_manager_prefix` | 6.0, `/wordpress`, both commands and default staged PHP | 5 | 10 | 2 / 4 |
| `file_manager_readonly` | 6.0 first passes both native execution paths, then upload-root permissions deny writes | 5 | 10 | 0 / 0 |
| `file_manager_fixed` | 8.0.7, authenticated backend works while unsafe anonymous connector is absent | 5 | 10 | 0 / 0 |
| `file_manager_absent` | Healthy WordPress with no File Manager plugin | 5 | 10 | 0 / 0 |
| `file_manager_unrelated` | Healthy unrelated HTTP service | 5 | 10 | 0 / 0 |

Every case runs its public check or execution twice. Selected sessions cover
`php/reverse_php`, `php/meterpreter_reverse_tcp`, and the owner's unchanged
target default `php/meterpreter/reverse_tcp`. Default cases remove remembered
payload selections, omit a PAYLOAD run override, and verify effective selection
and actual session provenance. Both commands have command-only and session
success paths; root command cases also disable AutoCheck. Every refusal mode
covers both commands with AutoCheck enabled and disabled.

Native calibration uses each selected payload through both write commands
before owner calls. Native HTTP and independent physical snapshots verify
ordinary GIF, UTF-8, backslash, quote and NUL-byte roundtrips, plus PHP command
proofs. The fixed target authenticates a real administrator, creates a directory,
uploads an ordinary GIF, writes UTF-8 text, retrieves exact bytes, and removes
the directory through the genuine plugin. An HTTP 404 alone is not its health
proof. Absent-plugin WordPress also authenticates successfully; the unrelated
service retains its exact health response.

Remote session APIs write and verify proof as UID 33. Target-side active socket
absence precedes local shell closure, and logical sessions/jobs return to idle.
FileDropper's real before/after existence checks and an independent physical
baseline establish owning payload-file cleanup before operator recovery.
Apache workers may persist after requests; their continued existence is not a
session-transport leak. Command-only payload files require explicit operator
recovery because no cleanup session exists.

The tested source/fixture revision is
`72857f7fbca06368c3e4df5a30d99b32efcb0cdd`. All six final runs retain their
current declared inputs; subsequent changes are verification/index reports.
The source owner SHA256 is
`f377741c2571223f53630f112e8cdeb21c60179dd280a5c3da9d2098b811fc25`.
The 39-case focused spec SHA256 is
`fc1096e97dac0d40c1f67ce35c07267298b69472a23b127ab828960394e4041e`.
The complete existing human guide and Scenarios remain byte-identical, SHA256
`fc3427a3149c42620cff5096faeeced3a8f34245ba233274fb31f6c02c2ed335`.

## Confirmed owner defects and repairs

1. HTTP 200 application errors were ignored. On a genuine read-only upload root,
   upload returns `warning: [errUploadFile, filename, errPerm]`; mkfile returns
   `error: [errMkfile, filename, errPerm]`. The owner previously announced a
   payload URL and requested a nonexistent file. It now checks command-specific
   success metadata and error/warning fields, returns a typed operation failure,
   and maps permission refusal to NoAccess.
2. Cleanup registration preceded creation. Refused writes registered nonexistent
   files. Registration now follows confirmed upload/mkfile creation. A confirmed
   empty file remains registered if the subsequent put fails; a failed mkfile
   stops before put and payload execution.
3. The genuine 6.0 connector removes raw NUL and unconditionally applies
   `stripslashes` to POST fields. An owning `mkfile+put` single-stage Meterpreter
   session died. The captured written file has 63,934 bytes, no backslashes and
   two NUL bytes, and passes PHP syntax. Independently generated native samples
   each have 63,966 bytes, 32 backslashes and no NUL. The vendor filter reproduces
   those statistics, but their dynamic data differs: they are not claimed as
   exact original owner plaintext. Put transport now preserves backslashes and
   NUL; upload bytes stay unchanged. Genuine native put calibration and two owning single-stage Meterpreter
   executions subsequently succeed, with remote proof,
   closure and physical file cleanup.

The first identical 36-case comparison has 27 failures before reply/lifecycle
repair and zero afterward. The expanded identical 39-case comparison retains
those 36 cases and has two failures on the reply-fixed source, zero on final
source, seed 7721; no pending/outside errors. Two separate full captured-payload
byte-model comparisons each fail before and preserve exact input bytes after.
These unit models double HTTP/payload boundaries; they do not establish native
execution. The genuine final profiles provide that qualification.

Strict owner lint and msftidy retain only the same two existing warnings:
ModuleDefaultPayload and RedundantPeerInPrint. Their exits remain 1 and 2;
there are no new offenses. All new Ruby fixtures/specs pass strict lint. Ruby
and PHP 7.3 syntax, exact example collection, source preparation, Compose limits,
module discovery and diff checks pass. No full local RSpec suite was run.

## Reproducibility and resources

[Recipes and commands](file_manager/README.md) live beside the module-to-profile
manifests under `test/module_targets/`. The guarded launcher runs one stack at a
time, with at most three capped containers: app 0.5 CPU/384 MiB, database 0.5
CPU/512 MiB, Framework 1 CPU/1024 MiB. Swap equals memory; PID limits and init
processes are asserted. Unrelated HTTP uses 0.25 CPU/128 MiB. Only loopback HTTP
ports are published. All 52 final cgroup counter rows have zero OOM/PID-limit
events; actual Docker inspection confirms the caps and no restarts/OOM kills.
Twenty-four final cleanup queries confirm no owned containers, networks or
volumes and an empty global container inventory. The advisory lock is free.

The official 6.0 archive contains `wp-file-manager/wp-file-manager-6.O.zip`, with
a capital O. Both outer and nested checksums are pinned. The fixed source uses
official SVN revision 3804192. All 916 file contents independently match the
official 8.0.7 package; the deterministic ZIP SHA256 is
`f654f8c8693123d267eac0cdca1b88d2e0006e09cc680fdfc0f82c42a7405b1f`.
The preparer can fall back to that immutable revision after the latest-download
URL changes. Vendor source is not patched. No project dependency is added.

## Retained failures and limits

Harness failures remain sealed separately: console resource binding, warning
versus error response shape, the driver's generic payload-failed fallback,
missing fixed-snapshot field, style corrections, and the absent-plugin empty
file-map cleanup failure. The first full profile also exposed the genuine put
corruption and a secondary unresponsive-console recovery path. Shutdown now
stops on postcondition failures, bounds emergency requests, and collects final
resource counters before state assertions. Earlier passing main/fixed runs were
replayed after the shared inspector correction. No failed or superseded run is
counted again.

Runtime targets are WordPress 5.2.4/PHP 7.3.11 with MariaDB 11.2.2, genuine File
Manager 6.0 and 8.0.7, and the recorded selected payloads. Official versioned 6.8
and 6.9 downloads/tags were unavailable; synthetic version-boundary unit cases
do not qualify those releases. Official 5.9 source is retained for dependency
and lower-bound investigation; no runtime claim is made for it. Other PHP/core
versions, nonstandard WP content directories and unselected payload/transport
combinations are not qualified.

The separate [publication follow-up](VERIFICATION-20261116-publication-followup.md)
records the preceding wpDiscuz checkpoint's macOS Mettle stderr failure on an
upstream Framework checkout. Cause/branch causality remain unverified; no
agent-initiated CI retry or cancellation was used to hide it.

## Evidence

The read-only checkpoint archive is
`/Users/dwelch/.codex/reports/file-manager-qualified-checkpoint-20261116`:
20 entries, manifest SHA256
`2bcaa4b80481d163bd9e5e3c70134c0e2a84dd5092eb0ca3c1733d5cf4a30a83`.
It references 32 immutable archives with 3,404 independently rehashed entries.
The six final profile seals contain 740 entries. They include all runtime logs,
source/fixture snapshots, effective options, independent native requests,
physical/session/closure evidence, resource inspection and cleanup audits.
