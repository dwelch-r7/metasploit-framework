# FreeSWITCH foreground execution and checks — 13 November 2026

## Summary

Current input-matched checkpoint: **226 modules qualified in their covered paths,
254 profiles and 2,408 functional examples**. This addition qualifies foreground
commands, checks and refusals. Unix sessions and Linux dropper delivery remain
active work; it does not establish those paths or Windows compatibility. The
broader module campaign remains incomplete. No PR is created.

All 16 cases pass across four serial profiles: 32 public calls, six actual
foreground commands, six accepted and six rejected authentications. A confirmed
check-method connection-error defect is fixed in a separate worktree, imported
and replayed against genuine services. Setup failures are preserved separately.

## What looks good

Run the [execution lab](freeswitch_execution/README.md):

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/freeswitch_execution/run.rb
```

| Family | Genuine configuration | Cases | Public calls | Containers |
| --- | --- | ---: | ---: | ---: |
| `freeswitch_exec_default` | FreeSWITCH, ClueCon password | 6 | 12 | 3 |
| `freeswitch_exec_custom` | FreeSWITCH, Unicode password with a space | 6 | 12 | 3 |
| `freeswitch_exec_acl` | FreeSWITCH, actual loopback-only ACL | 2 | 4 | 3 |
| `freeswitch_exec_unrelated` | Native authenticated OpenSSH fixture | 2 | 4 | 3 |

The original Drachtio image runs FreeSWITCH 1.10.10-release, commit 4cb05e7f4a,
on Debian 12 amd64. Its six original engine, library, module, client and
entrypoint hashes remain unchanged. The derived execution image adds exact
curl, wget, inetutils-telnet and Perl packages from the signed immutable Debian
snapshot of 1 January 2026. The [package catalog](freeswitch_execution/tools.json)
records versions, package hashes and the independently checked package-index
hash; the Dockerfile is the full build recipe. No application responses,
authentication checks, owning methods or protocol results are replaced.

Each profile runs target, Framework and disposable reporting PostgreSQL.
Application profiles cap total RAM at 1,664 MiB, CPU at 2.5 and tasks at 576;
unrelated OpenSSH uses 1,024 MiB/1.9 CPUs/448 tasks. RAM and combined RAM/swap
limits are equal. Target ports publish only on host loopback. An independent
observer verifies all actual roles/caps, the first cold console with two fresh
metadata files, and later cache reuse from this invocation only. The unchanged
guard retains its five-container hard limit and serializes startup/teardown.

Eight native phases verify genuine framed responses, correct/wrong passwords,
version, loaded event-socket module, local service health and exact system
output. Engine process birth and configuration hashes remain unchanged.
Tool binary hashes, package versions and the native package manifest remain
stable. Missing package metadata must match the exact ordered exclusions of
the base slim-image configuration; unexpected missing files, checksum changes
and configuration tampering remain failures. All 182 intentional omissions are
recorded in each applicable phase, rather than silently discarded.

Every public case repeats twice. Commands write exact per-run marker bytes,
return them through the real protocol and create files with the independently
observed target UID. Known proof files are removed through native control.
Wrong passwords and the public default against the custom-password target fail
without execution. ACL and real SSH targets receive no execution commands.
Thirty-two passive packet traces establish actual owning traffic, including
exactly one system command per successful call. Sessions and jobs finish idle.
All 24 cgroup queries record zero OOM/PID-limit events; memory-boundary counts
are also zero. The original authentication fixtures and human Scenarios remain
byte-exact. The module guide now links to the reusable container lab.

The source repair returns reason-bearing Unknown values for expected connection,
read and empty-banner failures, and ensures disconnect without replacing the
original result or body error. Classification and authentication/execution code
remain intact. Direct-owner regression reproduces 21 failures in 31 cases before
the fix and passes all 31 afterward; seven separately loaded helper cases pass.
Parent verification passes those 31 cases, six meaningful package-verifier cases
and the same seven helper cases. Synthetic boundary tests and native replay
remain distinct evidence.

Final run `20261113T160915-0a1fdc`, revision
`040d49fa1da257f1c0574891b4c52585424816cd`, completes naturally in approximately
5 minutes 20 seconds including startup. Controller, manager and observer exit 0;
all process IDs are absent. All 29 independent cleanup queries pass: every one
of the 12 containers and four networks is absent, no volumes were created, and
global container inventory is empty. The guard exits 0, its PID is absent and
both advisory locks are free. It removes four restarted unrelated MCP containers
during the lease; their images and unrelated volumes are preserved.

## Concerns

The first frozen functional run reaches no owner call: its package check
incorrectly requires empty `dpkg --verify` output despite intentional slim-image
exclusions, and its unrelated manifest maps port 8021 instead of real SSH port
22. Both setup errors are corrected after the complete run is sealed. A focused
verifier still rejects missing executables, checksum changes, an overridden
exclusion configuration and missing copyright files explicitly included by the
native rules. All original case descriptions remain present.

The second full run passes four cases. Eight command cases stop at Framework's
documented generic-payload cleanup guard, while two closed-port checks expose
the genuine check-method error. The fixture explicitly accepts `AllowNoCleanup`
only for generic command calls and independently removes its known proof files.
Two added cases prove the original guard still refuses unaccepted runs. The
guard and other production mixins are not changed. The isolated check repair
then receives fresh native replay; failures are not retried or reclassified as
success without a concrete correction.

Early tools-image builds separately record an older curl/library mismatch and
minimal Perl's missing modules. A compatible immutable snapshot and the exact
full Perl package resolve those prerequisites before functional testing.

Strict Ruby lint retains exactly nine pre-existing owner findings: five default
payloads, three legacy Notes values and one missing AutoCheck declaration. There
are zero new findings, no suppressions, and no spec/helper findings. Syntax,
module tidy, documentation tidy, catalog/configuration and diff checks pass.
The initial legacy documentation-heading warnings are corrected while preserving
all human Scenarios.

The known concurrent credential-core insert race remains deferred in the
separate multi-host authentication lab. Earlier Druid JavaScript, Superset
owner-RCE and WordPress admin exclusions remain unchanged. Inventory has 5,179
source files, 228 registered sources, 277 pending documented container hints and
zero stale reviews. Registration and partial command qualification do not prove
all module targets or payloads work.

## Suggestions

Complete independent native handler/session calibration, then real Unix Bash,
Perl and default-telnet sessions. Cover Linux x86/x64 shell and Meterpreter
payloads through both available curl/wget delivery paths, with process identity,
artifact cleanup and repeated execution. Keep the existing source check fix and
credential-library concurrency investigation separate. Continue valuable feasible
modules, including those without documentation hints.

## Verification receipts

All sealed files are rehashed, read-only and single-linked. Local immutable
records include:

- Stock native calibration: 16 entries, manifest
  `9c4272602acf4758e24f52b7ae96f0bbb7e8f74fa5e00669b39c19658239027d`.
- Tools native calibration and both failed builds: 37 entries, manifest
  `7923efb8d190bd2c7f0565fe5099a81085edc9cf0b5b717bb925cce60e896387`.
- Initial fixture baseline: 301 entries/83 inputs, manifest
  `556e7a0bf056c81814007b2297bcfe050cc76ce7c8c4858c72f92f78697fafe2`.
- Source/operator baseline: 405 entries/85 inputs, manifest
  `de49cbb1e53de9db408ab43eb650f3606fae33c5fdf9c9e99278b05eb5ef0aa0`.
- Isolated source fix `d495d537dfdd53f9a9fb33ff0354663bda840e28`: 83 entries,
  manifest `dcea7427469637b971041c6d0236ac46a66face7ab75de7d87a7579c3e77d76c`.
- Final native replay: 463 entries/85 inputs, manifest
  `2c58663115100bc7cb101884b3828d053ffc07209d74add3fd6c7380d9d46f73`,
  at `/Users/dwelch/.codex/reports/freeswitch-execution-commands-qualified-20261113`.
