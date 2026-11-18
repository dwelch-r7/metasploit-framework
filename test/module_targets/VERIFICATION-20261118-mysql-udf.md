# Native MySQL UDF execution, 2026-11-18

`exploit/multi/mysql/mysql_udf_payload` passes **9/0** on genuine MySQL 8.0.36,
with zero pending cases or errors outside examples. Fourteen owner calls and
12 real sessions cover native calibration, standalone execution and a borrowed
MySQL connection. This adds one runtime owner, one profile and nine cases,
reaching **300 runtime owners in covered paths, 611 qualified profiles and
4,283 historical functional cases**. The broader campaign remains active.

The [target guide](mysql_udf/README.md) gives the namespaced guarded command,
intentional lab configuration and reset contract. The pinned target runs as
mysql UID 999 with writable plugin directory and unrestricted secure_file_priv.
Two capped containers run at once; runtime limits are 640/384 MiB, 1/0.25 CPUs
and 128 PIDs each. Completed stacks are removed immediately. Only task-created
unused containers up over an hour are eligible for campaign cleanup; unrelated
containers are preserved. No PR is created.

## Native controls and setup corrections

The vendor client loads the exact existing 8,040-byte Framework ELF64 UDF,
registers sys_exec, executes exact marker/UID commands and repeats execution.
Actual wget download/chmod/execution and handler-generated Linux x86 shell and
Meterpreter executables then open responsive sessions as UID 999. Native SQL
contrasts establish FILE denial 1227, mysql.func SELECT denial 1142 and plugin
filesystem denial. These gates precede each relevant owner classification.
Loadable function requirements follow the official
[MySQL documentation](https://dev.mysql.com/doc/refman/8.0/en/create-function-loadable.html).

An initial wget package install exited 137 during metadata download at 512 MiB;
without cgroup counters its cause is unverified. A 1 GiB retry passed with all
recorded resource events zero. The image pins observed wget 1.19.5-16.0.1.el8_10.
Earlier Compose network/port and invalid SRVHOST attempts stopped before owner
execution and remain setup failures. An x64 payload selection was also rejected
before owner entry: this module declares x86 payload compatibility. Two generic
negative assertions in that attempt were false passes and are invalidated.
The final harness requires real owner entry and calibrates compatible payloads.
No target response handler, parser, UDF operation or payload encoder is replaced.

## Confirmed owner defects and repairs

The valid unchanged baseline runs seven cases with five failures. It produces
three bootstrapped RCE callbacks but reports IOError failures; its strict output
assertion stops before responsive owner-session proof. The genuine borrowed SQL
session discovers/installs an available UDF but returns nil and never reaches
staging. Catalog SELECT denial is caught as nil, then dereferenced with size.
Wrong-password and FILE denial controls pass independently.

Three separate worktrees repair those defects:

- Return the same successful Boolean after standalone or borrowed authentication.
- Preserve a catalog-query failure as a documented nil sentinel and abort before
  upload/replacement, or failed confirmation, with an actionable UnexpectedReply.
  Query error classes were already erased, so the diagnostic does not assume
  every failure is an access-denial error.
- Keep the owned SQL socket out of callback auto-abort until its pending reply
  completes, then disconnect from ensure. Background only the final Linux launch
  so a borrowed SQL connection returns; preserve earlier wget/chmod ordering and
  Windows commands. Genuine I/O errors still propagate, with no success inferred
  from a session count.

The callback regression uses the actual Payload on_session lifecycle and a real
Socket.pair, plus the actual Rex wget generator under several command-splitting
modes. The final aggregate focused suite passes **52/0**. Individual corrected
baselines are session 12/4, catalog library 22/2 plus module 7/5, and callback
11/6; each candidate passes. Initial synthetic adapter errors are retained as
harness-only evidence. Syntax and module tidy pass. Baseline-relative lint has
zero new offenses, 89 existing offenses, and zero spec/helper offenses.
The module-document checker retains six baseline warnings with zero new ones.
The static inventory has 5,179 sources, 4,294 pending selectable candidates,
223 pending documented container hints and zero stale source reviews.

## Final execution and recovery

Run `20261118T175130-1917eb` passes all nine cases with **57 unchanged declared
inputs**, 14 actual owner entries and 74 source trace events. The 12 sessions are
eight shells, three Meterpreters and one MySQL session; two RCE sessions calibrate
the native handler route and nine come from the owner. Each RCE session provides
responsive target proof, expected UID, a remote PID and a persisted record,
then remote process disappearance and database closure. The borrowed SQL session
retains its original connection ID, user and database through fresh/reused/forced
execution, remains responsive, then closes to zero clients.

Nine owner-generated ELF hashes match real target files; installed UDF bytes
match the existing Framework artifact. Eleven artifact snapshots distinguish the
module's intentional leftovers from explicit lab reset. Baseline files and an
empty sys_exec catalog are checked after reset. All eight cgroup captures are
zero. Independent inspection confirms absence of all **38 Docker objects** from
this cohort's manual probes and functional attempts. No task-owned containers
remain and no unrelated container is removed.

Windows runtime, Linux x86 database servers, other MySQL/MariaDB releases, TLS
and staged payloads remain unqualified. Existing human Scenarios are unchanged.
No full local suite is run; local runtime evidence does not imply fork CI success.

## Sealed local evidence

- Final native run: `mysql-udf-functional-20261118T175128`, 101 files; manifest
  `4e3c4bd7baccbc09fcaf4e71ed2ec5c52fa8ad713d8f8384a0705444983d7f7e`.
- Valid baseline: `mysql-udf-functional-20261118T173548`, 88 files; manifest
  `ae20f7b87881266bfe031478ab3d0e5a5e5e90a383876ceaa218183c517433f4`.
- Native artifact/fetch gate: `mysql-udf-native-fetch-20261118T172355`, 96 files;
  manifest `d6ea332a63dadc56da8e8d10f7060c1450d5c939a7511052ec326076241dae32`.
- Separate repair capsules: session `508db40949e357d00941e4772a6c588f20ff344ac4c021779715f94a7def86d3`,
  catalog `123da9b6dbf9cc9f806cd3f475b85921e70aabf3d7429614321f97b71bfa4182`,
  callback `eba8e356003d756da9b8d1ebf80ddeb2f3c1a27922120896fe6f22e40544bc27`.

Capsules retain exact inputs, command logs, native receipts and SHA256 manifests
outside Git. Related upstream source/build files do not establish exact provenance for the
Framework artifact; the published binary differs. Its actual hash is in the guide.
