# Pretalx container verification — 2026-11-12

## Summary

The [native Pretalx lab](pretalx/README.md) adds **23 passing functional cases,
50 public module calls and 10 exact loot files**. The verified campaign reaches
**219 modules, 219 profiles and 2,215 functional examples**.
The broader module campaign remains active.

Four profiles qualify the file reader
`auxiliary/scanner/http/pretalx_file_read_cve_2023_28459` against genuine 2.3.1
and 2.3.2 applications in production and development modes. The fifth profile
checks the companion execution module's production prerequisite only; its empty
qualified-owner list deliberately leaves remote execution unqualified.

Tested revision: `188ca72d7f5774a251c30d4d89a3050257abefff`. Final run:
`20261112T193741-f3942c`. Manager and live observer both exited 0.

| Profile | Cases | Public calls | Exact loot files |
|---|---:|---:|---:|
| `pretalx_2_3_1` | 8 | 18 | 8 |
| `pretalx_2_3_2` | 8 | 18 | 0 |
| `pretalx_debug_2_3_1` | 3 | 6 | 2 |
| `pretalx_debug_2_3_2` | 3 | 6 | 0 |
| `pretalx_production_guard` | 1 | 2 | 0 |

## What looks good

The targets use pinned community vendor images, genuine SQLite models, one
Gunicorn worker and one solo Celery worker. Redis carries real export jobs;
Framework persists actual loot/CVE records in separate PostgreSQL. Twelve
application/exporter/template files per image match the official release tags.
Independent controls publish a separate conference, attach an HTML resource,
queue an authenticated export and check the completed ZIP. Incorrect passwords
and denied speaker access are verified independently.

The affected file reader preserves exact bytes and paths containing spaces.
Production checks now report an unavailable version honestly; development
checks identify the disclosed affected/fixed releases. Default AutoCheck,
ForceExploit, disabled AutoCheck, repeated collection, missing/empty files,
incorrect credentials and insufficient organizer permissions are covered.
The companion returns Safe twice for an actual production-mode administrator.

Source fixes prevent hidden versions becoming `0`, refuse exported error pages
before loot/CVE reporting, encode comparison paths and decline unavailable
comparison responses. The error comparison removes only the genuinely random
404 heading and compares the remaining complete document with an actual 404
response. Legitimate nonmatching HTML remains accepted. The companion's debug
prerequisite runs before optional version discovery.

Focused source regressions use real module initialization, Rex responses and ZIP
serialization, with HTTP/authentication, proposal operations, delay and storage
explicitly doubled. Identical before/after pairs, seed 29461:

| Source pair | Cases | Before failures / exit | After failures / exit |
|---|---:|---:|---:|
| Initial version/error-document fix | 24 | 13 / 1 | 0 / 0 |
| Companion prerequisite regression | 27 | 1 / 1 | 0 / 0 |
| Encoded and unavailable comparison requests | 29 | 4 / 1 | 0 / 0 |

Native asset setup was corrected separately. Debug exports need a rebuilt offline
compression manifest. The bundled command hardcodes four threads and sometimes
fails while opening shared CACHE output. The transparent `assets.py` build
adapter limits that command to one worker and records its unchanged source hash.
Application and vulnerability sources remain unchanged; no successful responses
or ZIP files are simulated.

Four containers run serially, capped at **1,312 MiB, two CPUs and 480 tasks**:
target 512 MiB, Framework 640 MiB, PostgreSQL 128 MiB and Redis 32 MiB. Only the
target HTTP port is published on loopback. Temporary filesystems avoid persistent
Docker volumes. All final OOM/PID-limit counters are zero.

All 26 module export jobs succeeded before their downloads, excluding stale ZIP
success. Five independent native exports also completed. Empty session/job
vectors precede normal console reset. All **45 final resource-absence queries**
passed; ten additional queries cover the asset-inspection containers. Docker is
empty. The bounded cleanup guard exited 0, its PID is absent and its lock is free.

Reproduce the functional run serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb \
  pretalx_debug_2_3_2 pretalx_debug_2_3_1 \
  pretalx_2_3_1 pretalx_2_3_2 pretalx_production_guard
```

Focused regressions:

```sh
SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec \
  spec/lib/msf/core/exploit/remote/http/pretalx_spec.rb --seed 29461
```

The immutable final evidence has **736 entries and 54 inputs**;
manifest SHA-256 `be388a6d21aaef1b00a493fef8b8a6c1034add37789bd101049752fe9d063a0e`. Every file hash, read-only mode and
single link was independently verified. Earlier evidence remains separate:

| Run | Actual result / interpretation |
|---|---|
| `20261112T183857-f93102` | Original affected 8/2 failures; fixed 8/6. Confirmed false version/error loot plus an over-specific production version assertion. |
| `20261112T185326-d8fcaf` | First fix: affected 8/0; fixed 8/1 (space-path false loot). Both debug profiles fail native export preflight; no owner calls. |
| `20261112T191413-5a0d36` | Production 8/0 + 8/0 and companion 1/0; both debug setups fail during parallel asset generation. |
| `20261112T192923-fff6db` | Fixed hash seed: affected debug 3/0; fixed debug still fails asset setup. Seed alone is insufficient. |

## Concerns

No unresolved findings remain in the qualified paths. The companion's limited
file write, Python startup hook, command execution, sessions and cleanup remain
unqualified. Forced debug-mode reads and debug missing/empty-file behavior,
older releases, custom media URLs, proxy prefixes and alternate databases also
remain outside these results. A genuine file identical to the server's complete
error document is inherently ambiguous and is conservatively declined.

SMTP is intentionally blocked in this lab; production-mode proposal notifications
produce expected connection-refused diagnostics. Mail delivery is unqualified.
Owner/companion/spec/lab Ruby lint and module MSFtidy pass. The helper retains eleven
pre-existing lint findings; module documentation retains three unchanged long-line
warnings. Its human-authored Scenarios section is byte-exact (SHA-256
`5e6c9c9088285b0ad86ca0dd22842bfaa129bdee85b1c66d609e560775a0d00b`).

## Suggestions

Continue with a separate companion execution lab and independently prove its
startup-hook primitive before public exploitation. Keep the qualified inputs
stable and track session/process/artifact closure explicitly. The existing three
historical exclusions remain unchanged. The inventory contains 5,179 source
files, 221 registered sources, 283 pending documented container hints and zero
stale reviews. No pull request has been created.
