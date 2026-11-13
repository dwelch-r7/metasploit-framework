# Concrete CMS file-usage verification — 2026-11-13

## Summary

The [serial lab](concretecms/README.md) qualifies
`auxiliary/scanner/http/concrete_cms_file_usage_disclosure`. The current campaign
reaches **224 modules, 239 profiles and 2,332 functional examples**. The broader
valuable-module inventory remains open.

Tested revision: `f91f7889874a66a342cb8e6ccc398b522e62bab4`. Final run: `20261113T114616-5d617f`.
The final controller, manager and observer exited 0. All **26 cases and 52
public module calls** pass, with zero pending cases or errors outside examples.
Independent controls make 289 HTTP requests; 16 saved CSV files match the
application's actual page and usage models.

| Target | Cases | Public calls | Exact CSV files |
|---|---:|---:|---:|
| 9.5.0, root | 8 | 16 | 8 |
| 9.5.0, `/cms` | 8 | 16 | 8 |
| 9.5.1, root | 8 | 16 | 0 |
| Unrelated Apache 2.4.62 | 2 | 4 | 0 |

## What looks good

The original docker5 application images are pinned to immutable platform
manifests. Sixteen affected-release and fourteen fixed-release core files match
original Concrete CMS commits; the two removed controller/view paths are absent
on 9.5.1. Both images run PHP 8.2.35. Genuine MariaDB, Nginx, PHP-FPM,
authentication, uploads, page models and usage tracking are used throughout.
No application responses or permission checks are simulated.

Original APIs import generated PNG images, create public and private/draft pages,
add duplicate image blocks and persist references across two real page versions.
Anonymous access to the private page redirects to login; a real administrator
can view it. Wrong passwords fail. The affected anonymous dialog discloses the
private path; the fixed dialog returns 404 while ordinary site and administrator
access still work. Core hashes and usage rows remain unchanged after collection.

Cases cover single files, private Unicode paths, duplicate blocks and versions,
a bounded range containing an unused image, unused/nonexistent IDs, the default
50-ID scan, missing application paths and a native-proven refused TCP port.
Each owning case runs twice. Exact Nginx request sequences verify scan bounds.
Actual PostgreSQL rows verify vulnerability identity, host, port, protocol, CVE
and repeat idempotence in independent workspaces. Jobs and sessions are empty,
and target process identity remains stable.

The original module interpreted a binary UTF-8 HTTP fragment as Latin-1 through
Nokogiri, corrupting Unicode handles and paths in CSV. The fix tags a duplicate
response/body as UTF-8 before using the existing parser. Received bytes and
encoding remain unchanged, including frozen bodies. Port 80 stays the default;
duplicate Scanner host prefixes are removed. No shared HTTP library changes.

A separate worktree applies the fix. Its identical 13-case suite, seed 682601,
changes from **three failures / exit 1 to zero / exit 0**. The exact native
1,590-byte body has SHA-256
`dd65d40ea2847aa9c0b7ecd239ce210206dafc7f5061c26eb7e196f2d473a3c0`.
Rex wire parsing, Nokogiri and CSV generation/parsing are real; unit HTTP transport,
loot persistence and vulnerability reporting are doubles. The parent independently
passes all 13 cases. Container acceptance separately verifies real transport,
loot files and persisted reports.

Application profiles use **three containers capped at 1,920 MiB, 2.7 CPUs and
576 tasks**. Framework has 768 MiB; the target has 1,024 MiB. The unrelated
profile uses three containers capped at 960 MiB, 1.3 CPUs and 448 tasks.
Only application HTTP is published on loopback. Reporting data uses bounded
tmpfs and there are no persistent Docker volumes. Source/cache state stays
under ignored `tmp/` paths. The first console is cold; later profiles use only
that invocation's normal metadata. Actual prompts, BOOT records and both fresh
cache files are independently observed.

All **32 independent final cleanup queries** pass. Docker is empty; the cleanup
guard exits 0, its PID is absent and its lock is free. Final resource counters:
all memory-limit, OOM and PID-limit events are zero. No broad image or volume pruning is performed.

Reproduce serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/concretecms/run.rb

SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec \
  spec/modules/auxiliary/scanner/http/concrete_cms_file_usage_disclosure_spec.rb \
  --seed 682601
```

Final evidence: 747 files and 47 pinned inputs, manifest
`8b02b73d65971936b9a650cd5af3914fab96472b04f4665dd993eadc1f46278c`.
The parent-verified source comparison has 120 entries, manifest
`0a72abca36b74a49a3d31505d19a37e05218d2db9ced0c56a1d8547933a4346b`.
All copied hashes, read-only modes and single links are verified.

## Concerns

The first public baseline `20261113T111701-3b5f56` has 26 cases, nine fixture
failures and 34 actual module calls. Its native HTML oracle ignored the HTTP
charset. Its new page version was blank because the original cloning API does
not copy contents; adding a real image block fixed the seed. The initial ORM
flush hypothesis was incorrect and is superseded by source and actual database
rows. Those failures did not establish module defects. The 607-entry fixture
seal has manifest
`4dd8fce429ee14650896c52e0a7db5fca13da3af37d2a2f7ca82e2566776a34e`.

The corrected-oracle baseline `20261113T112656-4c1282` has 26 cases, eight proven
module failures and 44 actual calls. Eight saved positive CSV exports corrupt
Unicode; the independent native HTTP/API oracle is correct. Fixed and unrelated
profiles already pass. The manager exits 1, observer 0; all 32 cleanup queries
pass. Its 707-entry source-baseline seal has manifest
`807a3620c3f651c144ab9b7d05038d2ba18bd0c84a12947030b2398c1d7bc893`.
These failed runs remain separate from the final replay.

An interim parent cleanup audit ran while the next expected profile was active;
its seven exact resource checks passed and its global-empty check correctly
failed. That receipt is retained separately. The final 32 queries run only after
the complete controller terminates.

Earlier native preparation errors include an omitted Composer autoload,
an inferred `/lab` base directory, an unhandled startup connection closure and
expecting a 403 instead of the real private-page redirect to login. Corrected
native controls pass independently before module testing. A setup error is not
a module verdict. The Docker disk-cap restart belongs to the earlier Dolibarr
checkpoint; this Concrete CMS replay runs after the engine returns.

Changed Ruby passes strict RuboCop, syntax and module/module-doc checks. The
whole historical Scenarios-through-EOF tail, including its later Notes heading,
is byte-exact, SHA-256
`09722650b314d0a973132acae8dd15224c98c0fc8a895e5d0ce4696f2825b5f5`.
The full RSpec suite is not run. Older/later releases, other PHP/database engines
and other permission layouts remain unqualified. This auxiliary module has no
public check method; its collection entry point is exercised.

The preceding published revision `293619327340a16efc9848bc090c5c2d88a88090`
has 34 successful checks, one skipped, nine in progress and eighteen queued at
11:53 UTC. No failed check is reported at that snapshot; this is not completed
CI acceptance of the new checkpoint. Remote CI remains separate from the local qualification.

## Suggestions

Continue the full inventory: 5,179 files, 226 registered sources, 278 pending
documented container hints and zero stale reviews. Missing container hints do
not establish
infeasibility. The historical exclusions `druid_js`, `superset_rce_owner` and
`wordpress_admin` stay unchanged. Review FreeSWITCH event-socket authentication
and its companion execution paths next; image metadata and source documentation
are available, but native feasibility is not yet verified. No PR is created.
