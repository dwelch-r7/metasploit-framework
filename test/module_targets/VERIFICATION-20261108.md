# First module target verification checkpoint

Observed November 8, 2026, on revision `6f051ec36bf`, Ruby 3.3.13 on Intel macOS,
Docker Engine 29.9.2 (Linux/amd64) and Compose 5.6.1.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb --all
```

At this revision the command selected five families and returned exit status 0.
All **61 examples passed**, with **zero pending examples or outside-example
errors**, covering 20 registered runtime modules. The runner verified its exact
expected example counts, unchanged tested input digests and successful teardown
for every family. The whole invocation took about 5 minutes 37 seconds, including
container setup, five isolated console startups and teardown.

| Family | Actual target versions/configurations | Examples | RSpec duration, including console startup |
|---|---|---:|---:|
| Apache normalization | 2.4.49, 2.4.50, 2.4.62; guarded 2.4.49 | 16 | 64.56 s |
| Apache HTTP | 2.4.62, static content/Basic authentication/TRACE | 14 | 38.28 s |
| Memcached | 1.4.39 cachedump; 1.6.26 crawler | 4 | 37.13 s |
| PostgreSQL | 16.15, privileged password-authenticated role | 9 | 45.18 s |
| Redis | 6.2.14 open/authenticated; 7.2.4 protected defaults | 18 | 90.90 s |

The run retained `summary.json`, per-family `result.json`, `rspec.json`, logs,
rendered Compose configuration, image IDs, native target evidence, loot and
tested file digests under:

```text
tmp/module-target-tests/20261108T211027-a9e064/
```

These large local artifacts are intentionally untracked. Reproduce results with
the command above; image versions/digests and deterministic fixtures are tracked.
Module entry points were invoked through the acceptance console, not mocked.
Payload execution used fresh target-side proof files, and extraction checks read
the real loot. Native clients independently verified setup. The PostgreSQL suite
opened real protocol sessions; the Apache executable/command cases did not open
reverse shell or Meterpreter sessions.

## Discovered failure and correction

Baseline `7673832c306` failed the Redis file-upload public check: the scanner
implemented `check` instead of `check_host`. Its internal read-only configuration
probe also overclaimed a write on protected Redis 7. The focused correction,
developed in a separate worktree and integrated as `28d429e92c0`, exposes the
public check, returns Safe for protected defaults, and uses Appears when a write
has not been proven. Repeated successful uploads, configuration/data preservation
and checks on five Redis configurations were independently verified there.

The focused spec run passed 24 examples: 17 new module examples and seven
existing support examples. Its evidence was preserved locally under
`tmp/redis-file-upload-check-evidence/`. Intermediate upload failure cleanup is a
separate investigation; this checkpoint does not claim it is correct.

## Review and mechanical checks

- All eight added/changed test/tool Ruby files passed repository RuboCop.
- The changed older Redis module retains seven existing RuboCop warnings; no
  new offense was introduced. msftidy reports the older module exemption.
- All 17 changed module documents were compared with their upstream baseline
  using msftidy_docs. No new diagnostics were introduced; existing warnings in
  other documents remain. The revised Redis file-upload document passes.
- Whitespace checks passed. CLI inventory/list/invalid-family behavior was
  checked. A prior run with changed inputs was correctly rejected despite its
  assertions passing.
- Self-review confirmed target ownership, loopback bindings, digest pins,
  meaningful positive/negative assertions, repeat execution and evidence capture.

The new inventory also includes Python/Go sources and distinguishes helper files
and payload components. This is an initial checkpoint, not completion of the
repository-wide campaign. The remaining queue and limitations are in
[the campaign record](CAMPAIGN.md). No pull request was created.

## MySQL/MariaDB addition

The next batch reuses `spec/acceptance/mysql_spec.rb` with managed MariaDB 11.2.2
and Oracle MySQL 8.0.36 targets, both retaining default authentication plugins.
Native authenticated SQL health checks establish service readiness. Assertions
were strengthened from actual captures to require the configured user's hash,
returned account data and the server hostname, rather than only a generic save
message or version line.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mariadb mysql8
```

The strengthened run returned exit status 0: ten examples passed on each target,
zero failures/pending/outside-example errors, unchanged tested inputs and
successful cleanup. RSpec durations including console startup were 49.27 seconds
for MariaDB and 58.55 seconds for MySQL. Evidence is local at
`tmp/module-target-tests/20261108T212122-ddc203/`.

The two families cover five additional registered runtime modules, bringing the
verified checkpoint total to **25 modules, seven families and 81 cases**. Real
MySQL sessions, direct-host paths, queries, hash extraction and account enumeration
were observed. Framework credential persistence and downstream cracking were not
tested; the hash module's "Loot" message refers to its credential API, not an
actual loot file.

The existing MySQL spec retains 16 baseline RuboCop style offenses with zero new
offenses. Both added module-document links introduced no new msftidy_docs
diagnostics. No project dependency was added.
