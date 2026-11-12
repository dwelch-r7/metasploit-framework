# Pretalx execution verification — 2026-11-12

## Summary

The [execution lab](pretalx_execution/README.md) qualifies
`exploit/linux/http/pretalx_rce_cve_2023_28458` with genuine command execution
and sessions. The campaign reaches **220 modules, 222 profiles and 2,230
functional examples**. The broader campaign remains active.

Tested revision: `a87041cf65e3f9191408d475464e2a3852fa831b`.
Final run: `20261112T204929-9f7878`. The original manager and observer both
exited 0. All **16 cases, 32 public module calls and 20 module export jobs**
passed their assertions. Four actual sessions and four exact command-output
proofs were verified. The existing production prerequisite was requalified
after its source dependency changed.

| Profile | Cases | Public calls | Module exports | Sessions |
|---|---:|---:|---:|---:|
| `pretalx_exec_2_3_1` | 5 | 10 | 8 | 4 |
| `pretalx_exec_2_3_2` | 5 | 10 | 6 | 0 |
| `pretalx_exec_production` | 5 | 10 | 6 | 0 |
| `pretalx_production_guard` | 1 | 2 | 0 | 0 |

## What looks good

The separate fixture retains the qualified file-reader inputs. It reuses pinned
genuine Pretalx 2.3.1/2.3.2 images, SQLite models, serial asset generation and
real Celery/Redis exports. Twelve application/exporter/template files match the
official release source hashes. Runtime measurements establish Python 3.8,
UID/GID 999, the actual home directory, enabled user site and administrator
permissions. A copied native ELF executes successfully in the temporary payload
directory. No application vulnerability code or successful responses are mocked.

Independent native controls publish a separate conference and derive both the
decoded resource path and exporter destination from actual settings. Normal
exports succeed before and after the traversal control. A benign uploaded
`.pth` executes only on the affected debug target when one new Python process
starts. The fixed target rejects traversal; production writes an error document
without an import line. Hook removal and a second clean startup are verified.
All three independent standalone controls also passed before Framework testing.

The public cases cover repeated checks, default Bash sessions, commands with
AutoCheck disabled, forced fetched Meterpreter and quoted commands. Every case
runs twice. Session evidence includes exact remote file contents and ownership,
session type/peer, PID birth, remote shutdown, process disappearance and closed
SQL session records. Session/job registries, listeners and callback sockets are
checked before normal console reset. No fallback-cleanup journals were needed
in the final run.

Native execution exposed a source defect: raw command interpolation produced
Python `SyntaxError` for a command containing double quotes. The owner now uses
the existing Rex byte encoder inside one Python bytes literal. The same five
focused regressions, seed 68219, changed from **three failures/exit 1 to zero
failures/exit 0**. Cases include the exact captured command, ordinary commands,
single quotes, backslashes and literal line feeds. These regressions disclose
HTTP/auth/proposal/payload doubles and use a real isolated Python AST parser;
they never execute the generated hook. The final native run separately proves
real quoted-command execution and exact output twice.

The observer matches the specific export task ID in genuine worker logs against
its Celery result, captures the written hook and starts exactly one interpreter.
An HTTP healthcheck implemented without Python prevents accidental repeated
startup-hook execution. Negative assertions and operator restoration follow
actual export/interpreter completion. Handler waits remain 15 seconds.

Four containers run serially, capped at **1,312 MiB, two CPUs and 480 tasks**.
Only target HTTP is published on loopback; temporary filesystems avoid persistent
lab volumes. All final OOM/PID-limit counters are zero. All **36 independent
final resource-absence queries** passed. No containers remain. The bounded cleanup
guard exited 0, its PID is absent and its lock is free.

Reproduce serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb \
  pretalx_exec_2_3_1 pretalx_exec_2_3_2 \
  pretalx_exec_production pretalx_production_guard

SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec \
  spec/modules/exploits/linux/http/pretalx_rce_command_spec.rb --seed 68219
```

The immutable final evidence contains **510 entries and 70 inputs**, manifest
SHA-256 `25597b24f46ed5856b090a460a3077e9583be3c0aa6e68a2619d34cda31e7b82`.
The source regression archive has 116 entries, manifest
`c1430facd2d47372b6488d125ba0947bbeb8e492e6f7881d9af9468396ebf839`.
Every file hash, read-only mode and single link was independently verified;
the regression archive was copied independently from the fix worktree.

Earlier evidence remains separate:

| Run/control | Result and interpretation |
|---|---|
| Initial native control | Docker backing storage was full; the genuine export failed with ENOSPC. Capped tmpfs at the actual user-local path resolved storage; the payload tmpfs separately permits real ELF execution. No broad image/volume prune was performed. |
| `20261112T201450-603713` | Intentionally cancelled: observer selected a successful notification before the export. Fixture failure; no module verdict. |
| `20261112T202102-c09ded` | Affected 5/2 failures; fixed 5/0 and production 5/0. Quoted-command source defect confirmed. Bash actually passed session proof/closure, then failed an overly strict empty-stderr assertion. |
| `20261112T204043-1dd23d` | Affected 5/0; replay intentionally cancelled during the patched profile after review found a race introduced by shortening negative handler waits. Restored waits and explicit completion ordering before the final run. |

The Bash matcher allows only its exact captured close-of-unopened-descriptor
diagnostic, after successful session proof and shutdown. Other stderr remains
an error. The cancelled runs were cleaned, sealed and independently verified;
they do not substitute for the final qualification.

## Concerns

The owner leaves a persistent startup hook and an armed proposal description.
Tests explicitly remove the hook, including through actual session APIs, and
neutralize the disposable proposal description before repeating. This is
**operator restoration**, not automatic module cleanup. Retained uploaded
resources and proposals disappear when the disposable target is removed.

Older releases, other Python/user-site layouts, proxy prefixes, alternate
application databases and other privilege/authentication arrangements remain
outside these execution results. Literal line feeds in payload bytes have focused
parser coverage; the native quoted-command case uses shell `printf` to produce
its line feed. SMTP delivery is not qualified. The Docker backing filesystem
remains a storage limitation despite the capped writable temporary paths.

Changed owner/spec Ruby passes strict RuboCop and module MSFtidy. The module
guide retains two identical pre-existing long-line warnings. Its human Scenarios
are byte-exact, SHA-256
`4937fc0c62051582654afce06dabf4b4f47b79409e2952b5440f43ec096248fc`.
The full RSpec suite was not run.

## Suggestions

Continue the broader feasibility inventory. It contains 5,179 source files,
222 registered sources, 282 pending documented container hints and zero stale
reviews. The three historical exclusions (`druid_js`, `superset_rce_owner`,
`wordpress_admin`) remain unchanged. Strapi password reset has received source
and local-documentation review only; native feasibility remains unproven.
No pull request has been created.
