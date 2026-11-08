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

## Redis recovery qualification

Later review found that the initial Redis upload test compared output from a
multi-pattern CONFIG GET that Redis 6.2 does not support. Redis-cli returned zero
with an error string, so that assertion did not itself prove configuration
preservation. Independent verification in the fix worktree used individual
queries, but the committed suite needed correction. It now validates each
setting's field/value response before comparing configuration, exact keys and
sentinel data.

The expanded suite covers authenticated as well as open uploads, missing-directory
rejection and failed saves to `/proc` and a directory destination. Native Redis
commands independently establish each failure first. The `/tmp/..` case accepts
its filename setting and fails during SAVE; it is not a CONFIG filename rejection.
After each failed module run, state must be restored and two fresh uploads must
succeed. A fixture ensure path prevents a regression from contaminating later
examples.

Before integration, the corrected 22-case suite produced three expected failures:
two residual-state failures and a missing actionable directory error. Evidence:
`tmp/module-target-tests/20261108T213707-90bac7/`. The intermediate run whose
`/tmp/..` preflight incorrectly expected a CONFIG rejection was classified as a
test-setup mistake and corrected before this baseline.

The separately developed fixes were integrated as `9ca9bfcb642` (restore attempted
configuration changes and acknowledged keys) and `61bf769077f` (name a potentially
retained key when SETNX acknowledgement is lost). Native passthrough transport
tests forwarded genuine Redis traffic and dropped acknowledgements; they verified
that ownership warnings appear without deleting unacknowledged keys. A closed
module route prevented restoration and produced explicit cleanup warnings. These
transport experiments are retained as local evidence, not claimed as portable
container-suite cases.

The final Redis run passed **22 examples**, zero failures/pending/outside-example
errors, stable input digests and successful cleanup. RSpec duration including
console startup was 130.29 seconds. Evidence:
`tmp/module-target-tests/20261108T214044-1189ef/`. The focused unit run passed
40 examples (33 module and seven existing support examples). Current module bytes
match the independently tested fix exactly. Module lint retains three existing
UNKNOWN Notes warnings; changed specs and module documentation pass.

The current verified total is **25 modules, seven families and 85 cases**.
Each family's latest passing result was checked against the current source and
fixture digests, expected count and teardown status; the aggregate is recorded
locally in `tmp/module-target-verified-checkpoint.json`. No full-coverage claim is
made. Restore operations remain dependent on Redis connectivity and permissions;
uncertain key ownership requires operator inspection. Further module families,
session/payload variants and database-backed reporting remain in the campaign.


## Managed SSH and Samba addition

The SSH target reuses the existing Ubuntu/OpenSSH fixture and authenticates with
its native client before Framework runs. Two examples passed with a real SSH
session, Unix session tests and version detection. The observed service was
OpenSSH 8.9p1, Ubuntu package 3ubuntu0.18. The later native-console regression run
also passed all 14 HTTP examples and both SSH examples, with unchanged recorded
inputs and successful cleanup:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb http ssh
```

Evidence: `tmp/module-target-tests/20261108T215921-f2b9f9/`. RSpec durations were
73.71 seconds for HTTP and 81.69 seconds for SSH, including console startup while
an independent image build was running. The first SSH run took 62.98 seconds.

Samba passed all **20 examples**, zero failures/pending/outside-example errors,
unchanged input digests and successful cleanup. Evidence:
`tmp/module-target-tests/20261108T220931-692f38/smb/`; RSpec duration 72.59 seconds.
It exercised six production modules, real SMB sessions, direct-host enumeration,
file read/write operations through `post/test/smb`, default protocols and explicit
SMB 2/3 options where supported. The version scanner independently probes dialects
and does not accept that protocol option; its repeated suite case is not proof
of protocol restriction. The target was Samba 4.15.13 on the pinned Ubuntu base.
OS package versions may drift on rebuild; image IDs and native health output are
retained.

The verified checkpoint is **33 runtime modules, nine families and 107 cases**.
Tomcat and SQL Server qualification is separate and is not included in this count.

### Console infrastructure and setup corrections

The runner can now build the canonical Framework Dockerfile using a small
recorded dependency/build context and mount current source read-only at runtime.
The Ruby base is digest-pinned in the lab; normal Docker build defaults remain
unchanged. The console uses the host UID/GID and a per-run writable artifact
mount, joins only the lab's network, and publishes no reverse-listener port.
Warm builds reuse the dependency image despite module/spec edits. Container
inspection preserves native health output; fixture exec calls retain their
arguments, status and output. Eight existing child-process examples also passed.

The following setup failures were investigated rather than counted as module
defects:

- A host port mapping could not test `smb_enumshares`, which deliberately scans
  ports 139/445. The initial run was stopped after observing this mismatch; its
  partial assertions and cleanup are in `20261108T215200-c41ff2/smb`.
- Alpine's `id` rejected a numeric UID despite the account existing. Native
  `getent` verified the account and replaced that health check. The failed setup
  and successful cleanup are retained in `20261108T220303-683633/smb`.
- Tomcat opened a Java Meterpreter session, but the console entered it
  interactively while the harness expected its normal prompt. The interrupted
  run was cleaned up. Session tests now use background mode before explicit
  command proof; that observation alone is not full Tomcat qualification.
- A minimal build context initially omitted the public Gemfile example, causing
  an avoidable dependency-cache miss. The setup was stopped and corrected;
  `20261108T220902-08b782/smb` records interruption and cleanup.

Changed new tool/helper/spec files pass RuboCop. The older console helper and
SMB spec retain 15 and 22 baseline offenses respectively, with no new offenses.
All eight SSH/SMB module-document links introduce no new msftidy_docs diagnostics.
The full repository test suite was not run. Fork CI remains separately qualified:
an earlier Verify run failed in an untouched certificate/SID spec, and its MySQL
output-prefix failure passed on retry; neither has been labeled a campaign
regression without a baseline reproduction.


## SQL Server 2022 addition

The managed Microsoft Linux image, pinned by digest, independently authenticated
with native sqlcmd and reported SQL Server 2022 RTM-CU27-GDR, build 16.0.4305.5
(KB5126934), on Ubuntu 22.04.5. It uses Developer edition and the public SA fixture
credential already used by the repository's acceptance workflow. The native
preflight creates a small database/table, reads a marker and extracts the current
SA hash. Framework must return that exact hash, discover the seeded schema and
query the real row through both direct-host and MSSQL-session paths.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mssql2022
```

All **15 examples passed**, zero failures/pending/outside-example errors, unchanged
recorded inputs and successful cleanup. RSpec took 45.32 seconds including console
startup. Evidence: `tmp/module-target-tests/20261108T220931-692f38/mssql2022/`,
including `native-seed.log`, RSpec JSON and console output. The six additional
production modules bring the verified checkpoint to **39 runtime modules, ten
families and 122 cases**. The existing MSSQL spec retains 21 baseline RuboCop
style offenses; no new offense was introduced. Existing module-document links
introduce no new msftidy_docs diagnostics.

This target does not qualify Windows host operations, integrated authentication,
restricted database roles or other SQL Server releases. Database credential
persistence and downstream password cracking were not tested. The standard
non-managed acceptance invocation keeps its original 13 examples; only the
managed target enables the native seed/hash checks and two extra row queries.

Tomcat is not counted as verified. Its first complete 12-case run had seven
failures and successful cleanup. Two automatic-target cases and an HTTP401 reason
are being fixed separately; JSP generation raised ArgumentError before upload.
A Meterpreter command-output assertion was a harness issue, and upload staged
session delivery still needs investigation. Raw evidence:
`tmp/module-target-tests/20261108T220931-692f38/tomcat/`. These failures have not been
lumped together as seven module defects.

## SQL Server 2019 and eleven-family regression

SQL Server 2019 RTM-CU32-GDR, build 15.0.4500.2 (KB5128494), passed the same
15-case native-hash/schema/row and session/direct-host suite as SQL Server 2022.
Its Compose service extends the 2022 fixture, changing only the digest-pinned
image. The refactor's rendered configuration was compared with the independently
passing original configuration before the final run.

The eleven-family invocation at `tmp/module-target-tests/20261108T223836-aa3e46/`
passed every family except Redis. Five Redis cases failed while recording genuine
binary RDB output as JSON, before the assertions could finish. This was a harness
logging defect, not evidence of a Redis module failure. Native command logs now
mark UTF-8 text explicitly and encode invalid UTF-8 losslessly as Base64, while
returning the original bytes to the test. The corrected Redis run at
`tmp/module-target-tests/20261108T225149-10f7e8/redis/` passed all 22 cases in
137.69 seconds. Ten retained binary records decoded to genuine RDB data and
round-tripped exactly. Both runs completed target cleanup.

The cumulative verified checkpoint is **39 modules, eleven families, 137 cases**;
the first eleven-family invocation itself returned failure. All selected passing
results have exact expected counts, no pending/outside-example errors, stable
tested inputs and successful teardown. SQL Server 2019/2022 took 18.46/19.05
seconds in the eleven-family invocation. Authentication restrictions and Windows
host behavior remain unqualified.

The runner reuses only the two owning Framework source-metadata JSON files within
an invocation, before tests add module loadpaths. Each family still has its own
configuration directory. Native/container caches are separate; normal Framework
checksum refresh remains enabled. Cold/warm native and container workflows passed
against real targets. Recorded seeds and SHA-256 values make reuse inspectable.
Warm HTTP and SSH suites took 12.48 and 13.82 seconds respectively; these are
observations across different workloads, not a controlled speed benchmark.

## Tomcat fixes and Java profile

The integrated 12-case Java/login/check suite passed in 167.67 seconds at
`tmp/module-target-tests/20261108T225844-fe4ddf/tomcat/`, with stable inputs and
successful cleanup. The real target was Tomcat 9.0.123 with Java 17. Every exploit
ran twice, opened a session and created a previously absent native proof file;
Manager application state and deployment files were restored.

Four focused fixes were developed in separate worktrees with before/after
evidence: JSP WAR options (`a4a9ebbb588`), Manager identity/target/check handling
(`b0aec76c83a`), WAR cleanup after payload bootstrap (`af3cd7a91dd`), and executable
options forwarded after the format argument (`671799f3a9d`). The integrated
focused unit run passed **92 examples**, including existing support/stage specs,
with zero failures. Ordinary ELF/PE/Mach-O output and archive generation were
tested; this does not claim runtime execution on every advertised platform.

Java Meterpreter qualification explicitly uses Spawn=0. Immediate undeployment
caused captured in-process Java class-loading errors; delayed cleanup corrected
that path. Default Spawn=2 remains intermittent despite deferred cleanup. Native
transport controls connected with both spawn settings, so SIGPIPE/JDK options
and a universal undeployment-race explanation remain unproven. The payload's
default has not been changed. External handlers bypassing Framework's session
wait, Windows targets, Mac x86 explicit Mach-O signing and Linux x86 custom ELF
templates remain separate follow-ups.

The expanded Tomcat run at
`tmp/module-target-tests/20261108T231505-6bca03/tomcat/` passed all **14 cases** in
174.20 seconds, with stable inputs and successful cleanup. Both Manager APIs
also executed the Linux x86 command payload twice, each producing a fresh native
proof file. Manager state, deployed WAR/expanded application files and temporary
executables returned to their original state. This adds three runtime modules,
bringing the cumulative checkpoint to **42 modules, twelve families, 151 cases**.
Native execution was observed on Linux/amd64; ARM/emulation remains unqualified.

All eight changed module-document links introduced no new msftidy_docs diagnostics.
New specs/tool/helper files pass RuboCop; the older libraries and modules retain
baseline style warnings, including the existing hash/string styles on expressions
whose local deployment name became instance state. Eight existing child-process
examples also passed. The full repository RSpec suite was not run.
