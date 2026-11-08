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

## Managed LDAP addition

The existing Samba LDAP fixture passed **ten examples** in 14.58 seconds with a
warm isolated console. It was Samba 4.15.13-Ubuntu, built from the pinned Ubuntu
20.04 image. Native LDAP authenticated, enumerated five actual account objects,
read both seeded LAPS values and confirmed empty shadow-credential/RBCD values.
Framework then exercised five production modules through direct-host and real
LDAP-session paths. Evidence:
`tmp/module-target-tests/20261108T232404-50b9fc/ldap/`. The exact expected count,
zero failures/pending/outside-example errors, stable inputs and teardown passed.

The initial manifest expected eleven cases, while the existing suite defines
ten; that first invocation was rejected despite all ten assertions passing.
The count was corrected and the complete suite rerun. A native provisioning
attempt without the original fixture's SYS_ADMIN capability failed while setting
security.NTACL extended attributes, before LDAP started. With that capability,
native provisioning and health checks succeeded. No privileged flag, Docker
socket, host network or writable host-source mount is used. Setup evidence is
retained in `tmp/ldap-native-preflight-target.log` and
`tmp/ldap-native-capability-target.log`.

The cumulative checkpoint is **47 modules, thirteen families, 161 cases**.
Four module-document links introduce no new msftidy_docs diagnostics; the
existing Shadow Credentials document's CRLF content was preserved. This
LDAP-only fixture deliberately lacks full AD service advertisement and does not
qualify Windows AD, Kerberos, TLS, replication or state-changing actions.

## Tomcat default Spawn=2 diagnosis

Later native controls reproduced the distinction missed by earlier cold-JVM
experiments. Four payload calls from one long-lived JVM produced one connection
with the released class and inherited Catalina JDK_JAVA_OPTIONS, versus four
when that variable was cleared or Spawn=0 was selected. strace independently
captured a spawned Java17 process writing its startup diagnostic to an already
closed stderr pipe, receiving EPIPE and dying from SIGPIPE; parent wait4 confirmed
the signal. This establishes a cause in this fixture, not a universal Java fault.

The owning source is metasploit-payloads Payload.java. Its clean 2.0.257 source
at `74c28abb12135ad7dbdcdca2e934f414701f3c30` rebuilt to the exact installed class
SHA-256. A Java5-compatible experimental candidate drains output pipes instead
of closing them immediately. Warm baseline/candidate/release-recheck controls
gave **1/4, 4/4, 1/4** connections. Native Java8 controls passed for both classes.

The candidate also passed eight real default2 Meterpreter executions, four per
Manager API, with fresh native proof files and restored app/files state. It used
the existing per-run payload override, asserted the loaded class SHA and retained
the target's original Java options. No installed gem, production default or
external repository source was changed. Candidate source, patch, build commands,
native controls and baseline/trace/functional evidence are preserved locally in
`tmp/tomcat-spawn-evidence/`.

This candidate is not production-qualified: Tomcat reports running threads at
undeploy, and long-lived class-loader cleanup, Java5 runtime, SecurityManager
policies, other platforms/transports and owning-repository tests remain open.
An owning payload release and fresh integrated qualification are needed. The
routine Framework lab continues to select explicit Spawn=0 and retains the
default2 diagnostic. No experimental binary or external fix was committed.

## Axis2 and FTP additions

Axis2 1.4.1 and 1.6.2, original checksum-verified Apache WAR distributions on
pinned Tomcat/Java8, passed **twelve cases** in 176.57 seconds. Evidence:
`tmp/module-target-tests/20261108T232925-174571/axis2/`. Native controls establish
valid/invalid administration credentials and actual configuration disclosure on
1.4.1 versus rejection of the identical path on 1.6.2. Module HTTP traces must
show that path; a generic 404 cannot satisfy the negative case.

Both Java Meterpreter and command-shell payloads ran twice per release using
default Spawn=2: eight sessions, each with a fresh native file proving command
execution. Uploaded archives and Axis2's asynchronously refreshed service list
returned to baseline. Rejected deployment credentials must leave archives
unchanged. Input hashes, exact counts, zero pending/outside errors and cleanup
passed. No Windows/Linux native payload, SAP BusinessObjects, TLS or restricted
account qualification is claimed.

Initial Axis2 test corrections were kept separate from module defects: an
incorrect Ruby keyword argument prevented one LFI invocation; stale service-list
entries needed bounded native cleanup polling; handler-disabled negative cases
needed explicit AllowNoCleanup to reach authentication. The final complete
profile was rerun after these corrections.

FTP passed **thirteen cases** on ProFTPD 1.3.7c. The corrected initial run took
54.46 seconds at `tmp/module-target-tests/20261108T232925-174571/ftp/`; the combined
regression also includes explicit native version capture. Three independently
verified targets permit anonymous read/write, read-only or no access. Tests cover
the product banner, public login check, valid/invalid local credentials, anonymous
credential collection, access checks, FEAT/STAT/SYST and actual listing loot.
PASV and EPSV are both exercised. State-changing paths run twice and leave only
the original marker file. TLS, active data mode and database persistence remain
unqualified.

The first FTP module run had two over-specific banner assertions; Framework
intentionally normalizes the native ProFTPD banner to its product name. Eleven
other examples passed. Native fixture issues (an unavailable directive, a rejected
symlink log path and the distribution's default welcome file) were resolved
before module qualification; they are not module failures. The cumulative passing
profiles total **53 modules, fifteen families and 186 cases**. The new nine-case
SMTP profile and combined fifteen-family regression are still separate work.

## SMTP addition

Four Exim 4.95 profiles passed **nine examples** in 62.05 seconds, including a
cold isolated console. Evidence:
`tmp/module-target-tests/20261108T234115-3b7ffa/smtp/`. Native smtplib first
verified real recipient routing, known/missing local users, disabled/enabled
VRFY and open/closed remote acceptance. Framework tested the actual banner,
VRFY enumeration, RCPT fallback, absent users and unreliable catch-all detection.

Standard and sixteen-form extended relay scans ran twice per open/closed policy.
The extended cases must produce all sixteen outcome records. A positive result
also requires a previously unseen recipient to appear in Exim's native delivery
log as discarded by its local blackhole router. There is no configured forwarding
transport, so messages never go to an external recipient. This proves
acceptance/queueing detection, not forwarding across mail systems. Input hashes,
expected count, zero failures/pending/outside-example errors and teardown passed.

Native preflight caught configuration issues before module testing: bare VRFY
addresses needed explicit qualification permission; Exim's alternative-config
privilege behavior required its canonical config path; disabled VRFY returns
252; and the open relay ACL needed to preserve local recipient verification.
These are fixture corrections. All module examples passed on their first managed
run. TLS, authentication, EXPN and other MTAs remain unqualified.

The cumulative passing profiles cover **56 modules, sixteen families, 195 cases**.
SMTP was added after the fifteen-family invocation began and has a separate run.

## Combined fifteen-family regression

The invocation at `tmp/module-target-tests/20261108T233229-e3e685/` returned
exit status 0: **186 examples passed across all fifteen selected families**.
It ran from 23:32:29 to 23:49:00 UTC, including setup and teardown, while separate
native fixture and payload investigations ran concurrently. RSpec durations:

| Family | Examples | Seconds, including console startup |
|---|---:|---:|
| Apache normalization | 16 | 75.99 |
| Axis2 | 12 | 241.71 |
| FTP | 13 | 17.28 |
| HTTP | 14 | 10.27 |
| LDAP | 10 | 14.50 |
| MariaDB | 10 | 12.40 |
| Memcached | 4 | 8.34 |
| SQL Server 2019 | 15 | 15.89 |
| SQL Server 2022 | 15 | 16.91 |
| MySQL 8 | 10 | 16.15 |
| PostgreSQL | 9 | 18.15 |
| Redis | 22 | 99.88 |
| Samba | 20 | 50.16 |
| SSH | 2 | 19.30 |
| Tomcat | 14 | 121.29 |

The separately passing SMTP run contributes nine more cases. All sixteen
family results were checked for exact expected counts, zero failures/pending/
outside-example errors and successful cleanup. Every recorded tested-input hash
still matches the current file; the aggregate is retained in
`tmp/module-target-verified-checkpoint.json`. This checkpoint is **56 production
runtime modules, sixteen families and 195 functional cases**.

The newer specs and inventory tool pass RuboCop, and the SMTP module-document
link introduces no new msftidy_docs diagnostics. Fork lint passed at
`df93379ef5b`; other hosted workflows were still queued/in progress when checked.
The full repository RSpec suite was not run, and the repository-wide campaign
remains active. Further modules, target/session/authentication variants,
individually justified exclusions and recorded defects remain to be reviewed.
