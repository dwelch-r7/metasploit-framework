# Audiobookshelf authentication bypass lab

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb audiobookshelf_2_19_1 audiobookshelf_unrelated
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb audiobookshelf_2_19_0 audiobookshelf_uninitialized
```

The affected and fixed vendor images are pinned by manifest and configuration
digest in [profiles.json](profiles.json). Relevant application files are hashed
against official tagged source. Normal `tini -- node index.js` startup, real
SQLite, root login and a protected library are used; no HTTP or module method is
replaced. This tests the scanner, not media playback or external integrations.

Native controls verify `/status`, accepted/rejected login, authenticated library
access, unauthenticated rejection and raw versus encoded query behavior at both
root and `/audiobookshelf` paths. On the affected image the raw bypass reaches
API cache middleware and returns a request-level HTTP 500. A separate router
miss changes from 401 to the application's normal 404. The fixed image enforces
401 for both probes. Health, original Node process identity, protected SQLite
users/libraries and source files are checked before and after. An uninitialized
profile checks that state separately instead of assuming setup instructions
describe its HTTP behavior correctly. The known `/api/users` DoS is never used.

Functional examples use public `check` and `run`, repeats, subpaths, HTTP trace,
real authenticated headers, missing paths and refused ports. Actual Framework
SQL verifies vulnerability/service association, references and deduplication.
An authenticated baseline cannot confirm a bypass: the affected version can
still produce a passive `Appears` check, while `run` must preserve that prior
record without claiming a newly confirmed bypass. Loot remains empty.

One profile runs at a time with three containers, capped at **1,216 MiB/1.5 CPUs**:
target 320 MiB/0.3 CPU/96 tasks, PostgreSQL 128 MiB/0.2 CPU/64 tasks and Framework
768 MiB/1 CPU/256 tasks. Apache control totals 960 MiB/1.3 CPUs. Application
configuration/metadata and reporting database storage use bounded tmpfs; only
target HTTP is published on a random loopback port. Teardown precedes the next
profile. Root credentials and library details are public fixtures.

The two commands above permit keeping only one Audiobookshelf image cached on a
small Docker disk. After the first command finishes and its project is removed,
the inactive fixed image may be removed by its exact pinned reference before
the affected image is pulled. Removing cache does not remove the versioned
recipes or recorded evidence. Each command has its own genuine cold first
console and normal within-invocation metadata reuse. Systems with sufficient
disk can run all four selectors in one command.

Registration and native pilots do not prove module qualification. Consult the
campaign verification report for actual functional results and remaining scope.
