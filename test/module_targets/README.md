# Container module acceptance tests

These labs exercise real target software through Framework's public module entry
points. They complement isolated module specs and the existing protocol session
acceptance suites in `spec/acceptance/`. A container starting successfully does
not prove its configuration is correct, and a module completing does not prove
it achieved its purpose.

## Run

Use the Ruby version in `.ruby-version`, installed bundle dependencies, and a
running local Docker Engine with Compose supporting `up --wait`:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb --list
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb redis
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb --all
```

Run the [source-built MinIO lab](minio/README.md) with its dedicated build,
assembly and functional commands. The generic `--all` selector covers
manifest-backed labs; the inventory also exposes standalone `lab_profiles`.

The [Superset cookie lab](superset_cookie/README.md) supports its component
command and the shared guarded selector. Its manifest uses
`module_endpoint_network: default` to select the verified internal network of
its two-network gateway. Unopted families retain the single-network rule.

Use the guarded launcher for local campaign runs. It holds one user-scoped lock
across worktrees until tests and teardown finish, requires an empty container
inventory before startup, and refuses a resolved Compose plan exceeding five
containers including Framework and helpers. A refusal records
`setup_resource_refused` with no module verdict; it does not start or remove
containers. Handle existing containers explicitly before retrying.

The guard counts every resolved service conservatively, including disabled
profiles and zero replicas. Larger historical profiles need to be split before
local replay. Manual Docker commands, native smoke launchers and the original
runner do not acquire this advisory lock, so keep them in the same serial queue.
The guard limits container count; individual profiles still need suitable memory
and CPU limits. It counts resolved Compose services; nested runtimes need a
separate budget for the containers they create. After a cleanup failure it
refuses subsequent families.

The runner currently runs on Linux or macOS with a local Docker Engine. It
creates a fresh, uniquely named Compose project for each family,
waits for health checks, discovers random host loopback ports, runs its acceptance
spec, and removes its containers, networks and volumes. It uses an isolated
Framework configuration directory. Most profiles need no Framework database;
the credential-reporting profile creates its own disposable database.
Do not use the labs against external services; their credentials and intentional
weaknesses are public fixtures.

Each run retains reproduction commands, rendered Compose configuration, runtime
port mappings, image IDs, target logs, per-example console transcripts, RSpec
JSON, tested input digests, and cleanup status under `tmp/module-target-tests/<run>/<family>/`.
Loot remains in that run's `msf-config/loot/` directory. Unexpected example
counts, pending examples, changed inputs and cleanup failures cannot produce a passing family result. A failed assertion
is recorded as **unclassified**, not automatically a module defect. Inspect its
independent fixture preflight, target logs and raw console output first.

Labs using `console: true` reuse the canonical repository Dockerfile and
entrypoint through `framework.compose.yaml`. A small, recorded build context holds
the canonical dependency/build inputs; the complete current worktree is mounted
at runtime. Changes to modules or tests therefore reuse the dependency image.
The first build compiles gems and Go; subsequent labs share Docker's build cache.
Setup has a separate 30-minute
bound for that cold build, while functional tests keep their ten-minute bound.
The console sees read-only current source and a writable artifact directory at
its host path, so loot can be checked directly. Its process uses the host UID/GID.
Framework connects to internal service addresses and can receive reverse sessions
without publishing a listener. Independent host probes still use random loopback
ports. Container inspection retains image IDs and native health-check output;
native fixture exec commands are recorded in `native-commands.jsonl`.

Within one invocation, the runner also reuses Framework's two source-metadata
JSON files between families with the same console mode. They are captured before
tests add loadpaths or run modules, and copied into each fresh configuration
directory. Native and container caches are separate because their source paths
differ. Framework performs its normal checksum validation, and the runner records
the tested input SHA256 values. Seed files and their hashes are retained under
each family's `metadata-seed/` directory. A new invocation starts with a cold
metadata cache; settings, credentials and session state are never copied.
Metadata snapshots wait up to five seconds for an in-progress write, validate
the captured JSON bytes and publish those exact bytes atomically. An incomplete
snapshot remains a setup failure and cannot qualify a module.

## Layout and contribution contract

- `test/module_targets/<family>/compose.yaml`: real targets, configuration,
  health checks and optional source-built images. Pin versions and image digests.
- `test/module_targets/<family>/manifest.yml`: acceptance spec path, expected
  example count, module fullnames and service ports. Several modules may share
  one target family. `connection_env` maps services to an existing protocol
  suite's environment-variable prefix, avoiding duplicate suites.
  Integer port values retain ordinary TCP discovery. UDP-only targets use a
  mapping such as `open: {port: 69, protocol: udp}`; the runner asks Compose for
  the UDP mapping explicitly. Both host and internal module endpoints retain
  their `host`/integer `port` shape; `runtime.json` also records `transports`.
  This records the published mapping used for discovery; a service may support
  additional transports on its internal port, as in the TCP/UDP DNS profile.
  `console: true` adds the shared Framework console service; `test_env` supplies
  a suite's bounded fixture options without changing its ordinary defaults.
- `spec/acceptance/module_targets/<family>_spec.rb`: short functional cases,
  independent target validation and assertions on meaningful results.
- The shared console helper accepts explicit `endpoint_options` for modules
  whose registered server fields differ from RHOSTS/RPORT (for example NS or a
  single RHOST). Avoid injecting unknown endpoint fields or blank optional source
  addresses; keep normal module option validation enabled.
- Use an explicit bounded `command_timeout` for collection modules that perform
  many session round trips. Its ordinary default remains forty seconds.
- Prefer one invocation with several families so metadata is reused. Concurrent
  cold console starts can exceed the separate two-minute prompt deadline on
  development machines; classify that as setup failure and retry after the
  competing startup completes. No module result exists before a console prompt.
- Module documentation links to its family's lab instructions; keep target
  definitions here rather than copying Compose text across module documents.

Use authentic upstream images/source and verify the exact affected/fixed build.
Never replace a real application with a protocol stub that merely returns what
the module expects. Validate the target with its own client/API before invoking
Framework. Assert data, loot, a check result justified by actual target behavior,
or a session that can execute a command; don't assert only completion banners.

Keep setup time separate from execution time. Share a console where practical,
seed small deterministic datasets, bound network waits, and use one credential
per authentication case. Cover useful positive and negative behavior, supported
authentication modes, meaningful version boundaries, delivery families and
declared session types. Repeat state-changing paths to validate cleanup and
reuse. Document gaps rather than suggesting a narrow passing case proves every
supported target works.

All published ports must bind to `127.0.0.1` with random host ports. Avoid
privileged containers and Docker socket mounts. Host mounts are limited to
read-only source/configuration and the current run's writable artifact directory.
Container breakout, kernel, hardware and licensed targets need
individual feasibility assessment; a service container does not model a complete
operating system. Keep uncertain modules in the review queue.

The [Kubernetes profiles](kubernetes/README.md) are a documented privileged
exception for a genuine nested runtime. They share the engine kernel/devices
and use task-owned volumes and private namespaces, with no host bind mounts,
existing kubeconfig or Docker socket. Review that profile before selecting it
individually or through `--all`.

## Campaign queue

Individual source-reviewed target requirements live in `reviews.yml`, with a
source SHA-256 and concrete reason. The inventory marks a decision stale when
its source changes. A separate kernel, OS or device requirement does not mean
the module is broken or universally untestable; it identifies work that cannot
be qualified by a generic service container. Unreviewed modules stay pending.

```sh
ruby tools/dev/module_target_inventory.rb
ruby tools/dev/module_target_inventory.rb --json > tmp/module-target-inventory.json
```

The inventory enumerates current Ruby, Python and Go module sources and records
their digests, module-document paths, container hints and registered labs. Payload
components and external helper source are distinguished from selectable module
candidates. Registration means a
test exists, not that it passed. Neither a keyword match nor its absence settles
feasibility. Prioritize existing reproducible labs and service families that can
cover several valuable workflows, then version-specific vulnerable applications.
Record evidence-backed exclusions and failures in [the campaign record](CAMPAIGN.md).
The [earlier November 9 checkpoint](VERIFICATION-20261109.md) records its qualified
profiles and separate before/after module findings.
The [earlier published follow-up checkpoint](VERIFICATION-20261109-follow-up.md) records
86 modules, 31 families and 416 cases, including DNS, Linux, VNC, WebDAV, MQTT and mail
qualification at `e16b4bc4157`, with matching recorded inputs for its 31 families.
Later fixture/runner changes require fresh validation before updating that total.
The [earlier qualification record](VERIFICATION-20261109-jenkins-udp.md) records
**94 runtime modules, 36 families and 498 functional cases**, including the
subsequent Jenkins, TFTP, NTP, Jenkins-command and Elasticsearch profiles.
All recorded inputs are current, exact counts match and owned cleanup passes.
The [earlier qualification record](VERIFICATION-20261109-wordpress-ajp.md) records
**98 runtime modules, 38 families and 550 functional cases**, adding WordPress
discovery/login and Tomcat AJP file reads with independently verified repairs.
All selected recorded inputs remain current, exact counts match and owned cleanup
passes.
The [earlier qualification record](VERIFICATION-20261109-multicall.md) records
**99 runtime modules, 39 families and 572 functional cases**, adding genuine
legacy/current WordPress Multicall authentication with a verified 4.4 boundary
repair. All selected recorded inputs remain current, exact counts match and
owned cleanup passes. The separate administrator upload/session draft remains
unqualified while repeated staged-session behavior is investigated.
The [earlier qualification record](VERIFICATION-20261109-proxy-history.md) records
**102 runtime modules, 41 families and 592 functional cases**, adding Linux
history/hash collection and real HTTP forward-proxy detection. A separate
75-case HTTP/WebDAV/WordPress regression passes after the CONNECT parser repair.
All selected recorded inputs are current, exact counts match and owned cleanup
passes. The retained WordPress admin reproducer remains explicitly unqualified.
The [earlier qualification record](VERIFICATION-20261109-ansible-joomla-reporting.md)
records **104 runtime modules, 44 families and 629 functional cases**, adding
Ansible controller collection, Joomla API access checks and independent SQL
verification of persisted credentials. All selected recorded inputs are current,
exact counts match and owned cleanup passes. Ansible deployment, Drupal and
JBoss are separate investigations and are not included in this checkpoint.
The [earlier qualification record](VERIFICATION-20261109-consul-php.md) records
**105 runtime modules, 45 families and 640 functional cases**, adding genuine
Consul API/UI discovery. A separately proven PHP executable-wrapper repair is
included without claiming qualification of all its consumers. All selected
recorded inputs are current, exact counts match and owned cleanup passes.
The [earlier qualification record](VERIFICATION-20261109-drupal-jboss.md) records
**110 runtime modules, 48 families and 690 functional cases**, adding two
bounded Drupal profiles and genuine JBoss management/administration. Known
JBoss HEAD detection/output limitations are recorded explicitly. Ansible
deployment, Consul execution, JBoss payload sessions and WordPress admin remain
separate investigations. All selected recorded inputs are current, exact counts
match and owned cleanup passes.
The [earlier qualification record](VERIFICATION-20261109-consul-execution.md)
records **112 runtime modules, 49 families and 706 functional cases**, adding
actual Consul service/rexec command execution and a captured ACL-refusal repair.
Every selected count, recorded hash and owned teardown passes. Reverse Consul
sessions, Ansible deployment, JBoss payload sessions and WordPress admin remain
separate qualification work.
The [earlier qualification record](VERIFICATION-20261109-jboss-sessions.md)
records **114 runtime modules, 50 families and 718 functional cases**, adding
sixteen actual JBoss Java sessions across twelve cases with default Spawn=2.
Native controls distinguish the original target compiler failure from module
behavior. Every selected count, recorded hash and owned teardown passes.
Ansible deployment and WordPress admin remain separate qualification work.
The [earlier qualification record](VERIFICATION-20261109-credential-files.md)
records **117 runtime modules, 52 families and 730 functional cases**, adding
Linux SSH, Docker and RubyGems credential collection. All 32 recovered-credential
authentications pass after three separately reproduced module repairs. Every
selected count, recorded hash and owned teardown passes. Ansible deployment,
Erlang execution and WordPress admin remain separate qualification work.
The [earlier qualification record](VERIFICATION-20261109-etcd.md) records
**119 runtime modules, 53 families and 746 functional cases**, adding real etcd
version and exact JSON key collection. Sixteen cases pass after separately
captured discovery, serialization, authentication and error-handling repairs.
Every selected count, recorded hash and owned teardown passes. Ansible/Erlang
execution and WordPress admin remain separate qualification work.
The [earlier qualification record](VERIFICATION-20261109-zookeeper.md) records
**120 runtime modules, 55 families and 755 functional cases**, adding native
ZooKeeper version/permission controls and a genuine sliced TCP regression.
The original module silently stores six of eighteen environment fields; the
owning stream-read repair passes all nine final cases without assertion changes.
Every selected count, recorded hash and owned teardown passes.
The [earlier qualification record](VERIFICATION-20261109-kubernetes.md) records
**122 runtime modules, 57 families and 780 functional cases**, adding genuine
K3s enumeration and all four pod-execution delivery targets. Real Meterpreter
session discovery/routing exposes two owning namespace defects; five call sites
now use the existing accessor. All twenty-five cases, recorded hashes and
owned teardown pass, with no shared Kubernetes API changes.
The [earlier qualification record](VERIFICATION-20261109-rabbitmq-erlang.md)
records **125 runtime modules, 59 families and 809 functional cases**, adding
native RabbitMQ discovery/authentication and Erlang commands plus eight real
shell/Meterpreter sessions. Independent controls separate framing, completion,
session-lifecycle and broker-startup failures. All twenty-nine final cases,
recorded hashes and owned teardown pass. AMQP production source is unchanged.
The [earlier qualification record](VERIFICATION-20261109-grafana.md) records
**126 runtime modules, 60 families and 832 functional cases**, adding genuine
Grafana affected/fixed release pairs across all four branches. Separate owning
repairs expose the public scanner check and exclude fixed releases. All
twenty-three cases pass with exact repeated file bytes, current hashes and
owned teardown; two inherited source-lint offenses remain documented.
The [earlier qualification record](VERIFICATION-20261110-solr.md) records
**129 runtime modules, 63 families and 860 functional cases**, adding genuine
Solr discovery, Velocity and backup/restore execution. Two owning repairs preserve
shell variables and parent cleanup. All twenty-eight final cases, sixteen used
sessions, current hashes and owned teardown pass. Shared fetch-pool lifetime
and existing lint/documentation findings remain explicitly documented.
The [earlier qualification record](VERIFICATION-20261110-prometheus.md) records
**131 runtime modules, 64 families and 878 functional cases**, adding genuine
Prometheus discovery/configuration and Linux node_exporter collection. Native
controls establish seven healthy scrape targets, actual credential redaction and
quoted mount data before three shared-helper repairs. All eighteen final cases,
current recorded inputs and owned teardown pass. Provider discovery, Windows
exporter and database persistence remain outside that profile.
The [earlier qualification record](VERIFICATION-20261110-activemq.md) records
**132 runtime modules, 65 families and 892 functional cases**, adding genuine
ActiveMQ affected/fixed OpenWire execution. Native broker/JMS controls separate
fixture errors from a disabled-handler callback-lifetime defect. All fourteen
final cases, eight used sessions, current inputs and owned teardown pass.
Shared Fetch listener ownership remains separately under requalification;
this checkpoint requires exact route removal and records retained listeners.
The [Fetch requalification](VERIFICATION-20261110-fetch-lifecycle.md) retains
that same 132-module checkpoint after repairing shared HTTP/HTTPS ownership.
All 42 Solr/OpenWire cases pass stricter registry/listener/refusal checks, with
native component 62/10 to 62/0 and bounded artifact restoration.
The [earlier qualification record](VERIFICATION-20261110-docker-engine.md)
records **133 runtime modules, 66 families and 902 functional cases**, adding
real nested Docker information gathering without host sockets or extra
capabilities. Ten cases pass through native versions, Basic/TLS gateways and
actual reporting SQL after an unrelated HTML false-positive repair.
The [earlier integrated checkpoint](VERIFICATION-20261110-capture.md) records
**142 runtime modules, 71 families and 976 functional cases**. Six real-client
capture modules pass 32 cases after separate protocol repairs and an independently
found IMAP parser/completion follow-up. Genuine [Flink](VERIFICATION-20261110-flink.md)
file reads and Java sessions add 24 cases; [Jolokia](VERIFICATION-20261110-jolokia.md)
adds 18 while preserving existing broker bridges and cleaning only confirmed
owned connectors. All selected input hashes, exact counts and owned teardown
pass. The [NFS/reader checkpoint](VERIFICATION-20261110-nfs-reader.md)
records **145 runtime modules, 73 families and 1,002 functional cases**. Two
[NFS/RPC scanners](VERIFICATION-20261110-nfs.md) add 18 cases after a captured
UNFS3 export-marker repair. The [ActiveMQ source reader](VERIFICATION-20261110-activemq-disclosure.md)
adds eight cases with exact stock JSP bytes and fixed/unrelated refusals.
A separate Flink discovery repair passes a fresh 24-case runtime replay.
The [database capture checkpoint](VERIFICATION-20261110-database-capture.md)
records **147 runtime modules, 75 families and 1,031 functional cases**. Genuine
MySQL/MSSQL clients add 29 capture cases after separate binary-response,
empty-password and NTLM reporting repairs. Native wire and direct SQL verify
actual bytes/context while preserving UNTRIED semantics; parent focused tests
pass 77 examples. The [FileServer checkpoint](VERIFICATION-20261110-fileserver.md)
records **148 runtime modules, 76 families and 1,040 functional cases**. The
ActiveMQ FileServer exploit passes nine cases and twelve used sessions after
separate URI, classloader and cleanup-option repairs. Native counterfactuals
separate the fixture environment failure from stale-JAR cascades; false-option
preservation and explicit operator restoration pass twice. Parent focused tests
pass 20 examples. The [NiFi checkpoint](VERIFICATION-20261110-nifi.md)
records **150 runtime modules, 77 families and 1,055 functional cases**. Two
unchanged NiFi scanners pass 15 cases against genuine HTTP/HTTPS releases with
native authentication controls, exact reporting and workspace isolation.
Readiness and expected-negative fixture failures remain separate from module
verdicts. WordPress admin sessions remain explicitly unqualified. SIP, Gitea,
remaining NiFi modules and other feasible targets continue separately.
The [Tomcat checkpoint](VERIFICATION-20261110-tomcat-defaults.md)
records **150 runtime modules, 78 families and 1,069 functional cases**. A
separate stock Java8 profile passes14 cases with real default Spawn2 and twelve
used sessions. The strengthened shared spec also passes a fresh Java17 explicit
Spawn0 replay. Native identical-payload controls retain the Java17 default-spawn
limitation. Current hashes and owned teardown pass for both profiles.
The [Gitea checkpoint](VERIFICATION-20261110-gitea.md) records
**152 runtime modules, 80 families and 1,097 functional cases**. Two Gitea
execution modules pass28 cases after separate cookie/path/detection, migration
href and confirmed-ownership cleanup repairs. Native controls precede46 public
calls and twelve used sessions; parent focused tests pass27 examples. All current
input hashes and owned teardown pass.
The [Hadoop checkpoint](VERIFICATION-20261110-hadoop.md) records
**153 runtime modules, 82 families and 1,116 functional cases**. Genuine Hadoop
passes19 cases with its original owner after native-proven fixture corrections.
Six used sessions, exact repeated proof/cleanup, current hashes and owned
teardown pass. At-least-once YARN retries, operator restoration and19 inherited
undeclaredTARGETURI warnings remain explicit qualification limits.
The [NiFi processor checkpoint](VERIFICATION-20261110-nifi-processor.md) records
**154 runtime modules, 85 families and 1,135 functional cases**. The unchanged
NiFi processor module passes 19 cases, ten used shells and exact canary/graph
restoration after fixture observer, bearer-option and compatibility corrections.
Current hashes and owned teardown pass; unsupported Fetch, TLS and other limits
remain explicit.
The [SIP checkpoint](VERIFICATION-20261110-sip.md) records
**161 runtime modules, 89 families and 1,177 functional cases**. Seven SIP/Manager
modules pass42 cases after native-proven enumeration, deregistration and capture
repairs. Native password recovery, current inputs, parent41 focused cases and owned
cleanup pass; TLS trust and legacy policy limits remain explicit.
The [Spark checkpoint](VERIFICATION-20261110-spark.md) records
**163 runtime modules, 91 families and 1,204 functional cases**. Two genuine Spark
profiles pass27 cases and ten used sessions after a native-proven form encoding
repair. Corrected3.1.3 advisory coverage, auth/negative controls, current hashes
and owned cleanup pass; REST option and other scope limits remain explicit.
The [InfluxDB checkpoint](VERIFICATION-20261110-influxdb.md) records
**164 runtime modules, 92 families and 1,220 functional cases**. InfluxDB passes16
cases in60.7 seconds with its original owner, exact JSON loot, native auth/role/
query/path controls and repeated state checks. Current hashes and owned cleanup
pass; fixture attribution and1.x scope remain explicit.
The [NiFi H2 checkpoint](VERIFICATION-20261110-nifi-h2.md) records
**165 runtime modules, 95 families and 1,233 functional cases**. H2 adds13 cases;
scanner15 and processor19 are requalified after the shared state-body repair.
Native DTO/state/delay controls, parent37 focused examples,120 current inputs and
all187 exact object checks pass. Shell-use and operator-cleanup limits remain
explicit.
The [SMB directory checkpoint](VERIFICATION-20261110-smb-directory.md) records
**168 runtime modules, 98 families and 1,265 functional cases**. Three SMB modules
pass 32 cases across three identified runs, with 64 operations, eight real SMB
sessions, exact interface notes, credential/loot proof and repeat checks.
Parent 46 focused examples, 96 current inputs and all 147 cleanup checks pass.
Native/observer attribution, Windows limits and the serial resource cap remain
explicit.
The [NiFi credential checkpoint](VERIFICATION-20261110-nifi-credentials.md) records
**169 runtime modules, 99 families and 1,276 functional cases**. NiFi credential
gathering passes 11 cases with 22 public calls, 11 real used sessions, exact
decrypted JSON and repeat-stable session-origin SQL credentials. Parent 26 focused
examples, 73 current inputs, lint and all 16 owned cleanup checks pass. Original
failures, derived boundary files and unqualified versions remain explicit. Only
campaign containers may run on the development host, one project/five containers
at a time, with teardown after each run.
The [Druid checkpoint](VERIFICATION-20261110-druid-compact.md) records
**171 runtime modules, 103 families and 1,310 functional cases**. Two Druid modules
pass34 cases across two recorded invocations. Compact JavaScript profiles use five
containers and verify actual socket writes and native command bytes. Earlier
JNDI/session passes retain ten used sessions, exact PID removal and wire evidence;
their larger historical profiles require redesign before local replay. Parent
103 qualified inputs, 22 source and26 observer examples, ten-file lint and301 resource/alias
checks pass; inherited source/docs lint and failed fixtures remain explicit.
The [OpenTSDB checkpoint](VERIFICATION-20261110-opentsdb.md) records
**173 runtime modules, 107 families and 1,359 functional cases**. Both original
OpenTSDB modules pass49 cases across affected/fixed profiles, with98 public
operations and12 used sessions. Independent native controls,87 current inputs,
all235 imported files and32 cleanup checks pass. Original fixture failures,
public Basic negotiation, Fetch scope and operator restoration remain explicit.
The [Gogs hook checkpoint](VERIFICATION-20261110-gogs-hooks.md) records
**174 runtime modules, 108 qualified families and 1,369 functional cases**.
Gogs hooks pass ten cases after capture-backed path, check and commit-lifecycle
repairs, with four used owning sessions and two separate native calibrations.
Parent 22 focused examples, 60 current inputs, all 134 imported files and exact
owned teardown pass. Inherited lint, operator cleanup and unqualified rebase,
Windows, x86 and branch variants remain explicit.
The [GeoServer checkpoint](VERIFICATION-20261110-geoserver.md) records
**176 runtime modules, 111 qualified families and 1,379 functional cases**.
Two unchanged GeoServer modules pass ten cases across three official releases,
with four proven commands, four exact XXE loot files and fixed-release refusals.
The original three failures were invalid public-version expectations; corrected
tests require reason-bearing Unknown and default AutoCheck blocking before
explicit override tests. Parent six recorder examples, four-file lint, 51
current inputs, all 145 imported files and 28 independent cleanup queries pass.
Sessions, other platforms, built-in roles and additional data paths remain pending.
The [Grafana checkpoint](VERIFICATION-20261110-grafana-expression.md) records
**177 runtime modules, 115 qualified families and 1,393 functional cases**.
Grafana SQL expressions pass fourteen cases with four used owning Bash sessions,
two separate native payload calibrations and exact quoted UTF-8 output. The
module-local byte-encoding repair preserves request bytes and corrects their
declared length; session dispatch/transfer failures remain separate fixtures.
Parent 82 current inputs, all 233 imported files, 362 export entries, lint/docs
and 29 cleanup queries pass. Positive RCE scope is 11.0.0; 11.0.5 RCE,
other release branches and additional delivery/platform paths remain pending.
The [Gogs repository checkpoint](VERIFICATION-20261110-gogs-repositories.md)
records **178 runtime modules, 118 qualified families and 1,408 functional cases**.
All 25 Gogs cases pass after capture-backed observer corrections, including
existing-repository ref/parent/feature proof and fixed-release negatives. Eight
owning sessions are used, alongside five native calibrations. The earlier
failures remain preserved. Parent 81 current inputs, all 276 imported files,
528 export entries and 52 exact cleanup queries verify. Other platforms,
same-instance reset and unchanged-existing-repository repeatability remain
pending.
The [Flowise checkpoint](VERIFICATION-20261111-flowise-recovery-sessions.md)
records **182 runtime modules, 124 qualified families and 1,420 functional cases**.
All six selected Flowise profiles pass 12/0, including repeated account takeover,
genuine recovery, JWT/Basic authentication, used Meterpreter/Python sessions and
fixed-release refusals. Earlier fixture failures remain preserved. Parent 102
current inputs, all 475 imported files, 599 immutable entries and 61 exact cleanup
queries verify. Production owners and human Scenarios are unchanged. Mail scope
is unverified local SMTP TLS; other platforms and listed paths remain pending.
The [MinIO integrated checkpoint](VERIFICATION-20261111-minio.md) records
**184 runtime modules, 126 qualified lab profiles and 1,429 functional examples**.
Both MinIO profiles pass 6/0 and 3/0 with genuine native controls, complete JSON
loot, exact SQL reporting, real S3 reuse and fourteen restored client states
through Linux shell/Meterpreter sessions. The original invalid-JSON defect is
repaired; original failures and a bounded fixture timeout remain preserved.
Parent 101 focused examples, twelve-file lint, whole 557/171-file imports and
sixteen exact cleanup queries per profile pass. An unused Gogs-helper difference
is explicitly reviewed, with current Gogs fixes preserved. Other OS/session
paths and the unrelated UDP CI investigation remain pending.
The [Superset version checkpoint](VERIFICATION-20261111-superset-versions.md)
records **186 runtime modules, 128 qualified lab profiles and 1,447 functional
examples**. The shared guarded command passes fourteen cases on 2.0.0 and four
on 2.0.1, with native controls before and after each profile, actual SQL reporting
and repeat execution. The 2.0.1 baseline exposed false `Safe` checks in both
Superset owners; the corrected boundary also permits the gatherer's default
AutoCheck path. The RCE owner has check-only coverage and remains unqualified
for exploitation. Explicit internal-network selection now supports the gateway
through the shared runner. All 73 focused examples pass; earlier qualified
families retain their original receipts through an exact reviewed comparison of
the unchanged default runner path, rather than a claim of fresh runtime replay.
Parent verification confirms 68 current input files, 129 byte-preserved imported
run files, a 206-file seal and 23 independent cleanup queries. Other releases,
rotated keys and the separate RCE execution paths remain pending.
The [native RCE preparation](VERIFICATION-20261111-superset-rce-native.md) also
passes two genuine SQL/permalink/deserialization cycles with exact cleanup and
zero Framework calls. It adds no qualified owner, profile or functional example.
The [RCE owner investigation](VERIFICATION-20261111-superset-rce-owner.md)
verifies the binary permalink repair in the real application and passes eleven
isolated source examples. The owning shell ran and closed cleanly; Meterpreter
shutdown, a residual row and unreached repeat/negative paths keep the five-case
owner profile unqualified. The repaired source retains four passing 2.0.1 cases.
The qualified totals remain unchanged; registration now covers 188 sources.
The full campaign remains incomplete while feasible, valuable modules await review
or functional verification.
See [deferred investigations](DEFERRED.md) for retained failures that remain
unqualified after bounded investigation.

The [Ray job and architecture checkpoint](VERIFICATION-20261111-ray-jobs.md)
records **188 qualified modules, 132 lab profiles and 1,476 functional examples**.
Both file-read profiles pass eight cases each on refreshed sources. Genuine
Ray 2.6.3 job profiles pass eleven x64/x86 cases and two AArch64 payload cases,
with seven independent payload calibrations and fourteen owning sessions used
and closed normally. A fresh exact-listing assertion and bounded 512-file log
capture repair two harness failures. Ray 2.8.1 now uses 1,536 MiB after its
memory monitor rejected a native task at the earlier cap. The original failures
remain preserved. All containers/networks are independently audited absent.
Registration covers 190 sources, with 314 documented container hints still
pending review; the campaign remains incomplete. No PR is created.

The [Ray CPU profile checkpoint](VERIFICATION-20261111-ray-profiler.md) records
**189 qualified modules, 134 lab profiles and 1,488 functional examples**.
Ten x64/x86 cases and two AArch64 payload cases pass on genuine Ray 2.6.3,
covering all four declared targets with seven independent payload calibrations
and fourteen owning sessions used and closed normally. Ordinary py-spy profiling
is permission-denied under the default capabilities, while independent command
markers and the owning exploitation paths still execute through the real API.
No extra capability or application patch is needed for those verified RCE paths.
Both profile teardowns pass nine exact-resource/root inventory queries each.
Registration covers 191 sources; 313 documented container hints remain pending.
The broader campaign remains incomplete, and no PR is created.

The [modern Ray log checkpoint](VERIFICATION-20261111-ray-modern-logs.md) records
**190 qualified modules, 135 lab profiles and 1,499 functional examples**.
Eleven cases pass on genuine Ray 2.56.0 with fourteen exact new loot files,
repeated discovery/node/glob paths, missing/unknown/unrelated negatives, and
independent native controls before and after. The normal nine-process dashboard
required a measured resource budget: Ray is capped at 5,120 MiB/one CPU, and the
three-role owner profile totals 5,952 MiB/2.1 CPUs. Actual target peak was about
4.0 GB with no limit events in the final run. Native resource/probe failures are
preserved separately; none is classified as a module defect. Registration covers
192 sources, with 312 documented container hints pending review. At that checkpoint,
multi-node and fixed-version comparisons remained separate.

The [Ray log fixed-release comparison](VERIFICATION-20261111-ray-fixed-logs.md)
advances the checkpoint to **190 modules, 136 profiles and 1,506 examples**.
The current affected replay passes eleven cases; seven fixed 2.57.0 cases pass
Safe/AutoCheck, forced traversal/absolute-path refusals and ordinary log loot.
Native gRPC and server-log errors distinguish correct denials from a broken
HTTP API. All 54 distinct inputs match current source; seventeen root cleanup
queries pass with global containers empty. Registration remains 192 sources and
312 pending documented hints. Multi-node and broader campaign coverage remain.

The [Memcached UDP checkpoint](VERIFICATION-20261111-memcached-udp.md) advances
coverage to **192 modules, 137 profiles and 1,516 examples**. Ten cases verify
two genuine releases, disabled UDP, closed ports and repeated batches. Twenty
actual module calls have distinct wire records and checked reporting arguments;
dynamic amplification matches captured replies. Four containers are capped at
960 MiB/1.3 CPUs, and ten exact cleanup queries leave Docker empty. Registration
is 194 sources, with 310 documented container hints still pending review.

The [FTP bounce checkpoint](VERIFICATION-20261111-ftp-bounce.md) advances coverage
to **193 modules, 138 profiles and 1,526 examples**. Ten cases and twenty actual
module calls verify ProFTPD relay behavior against received Apache connections,
authentication/policy negatives and mixed ports. The four-role cap remains
960 MiB/1.3 CPUs. The original native-log matcher failure is preserved, all
43 current inputs match and ten exact cleanup queries pass with Docker empty.
Registration covers 195 sources; 309 documented container hints remain pending.

The [Java registry/JMX checkpoint](VERIFICATION-20261111-java-jmx.md) advances
coverage to **195 modules, 139 profiles and 1,535 examples**. Nine cases and
eighteen actual module calls verify registry references, dynamic proxies,
authentication, empty bindings and HTTP negatives with two passing native phases.
A confirmed empty-binding scanner error is fixed and independently replayed.
Four containers are capped at 1,536 MiB/1.3 CPUs; ten exact cleanup queries leave
Docker empty. The preserved eighteen-case DGC profile needs a historical JVM and
remains unqualified. Registration covers 197 sources, with sixteen individual
reviews and 308 documented container hints pending.

The [Ollama checkpoint](VERIFICATION-20261111-ollama.md) advances coverage to
**196 modules, 140 profiles and 1,547 examples**. Twelve cases and twenty-four
actual module calls verify real model metadata, running/installed/empty states,
authentication, multiline prompts and negatives. Two confirmed reporting errors
are fixed in separate source worktrees and replayed against the genuine server.
Three containers are capped at 1,856 MiB/1.6 CPUs; nine exact cleanup queries leave
Docker empty. Registration covers 198 sources, with 307 documented hints pending.

The [RocketMQ checkpoint](VERIFICATION-20261111-rocketmq.md) advances coverage to
**197 modules, 141 profiles and 1,555 examples**. Eight cases and sixteen actual
module calls verify genuine 4.9.4/5.1.1 discovery, version checks, unsupported
requests and refused connections. A confirmed variable-header parser crash is
fixed in a separate worktree and replayed with native before/after controls.
Three containers are capped at 2,048 MiB/1.5 CPUs; eight exact cleanup queries
leave Docker empty. Full exploit/session paths were unqualified at this discovery
checkpoint. Registration covers 199 sources, with 306 documented hints pending.

The [RocketMQ execution checkpoint](VERIFICATION-20261111-rocketmq-execution.md)
advances coverage to **198 modules, 144 profiles and 1,561 examples**. Six owning
sessions cover Bash, default fetched staged Meterpreter and AutoCheck-disabled
execution; two fixed-target refusals and four marker-proven generic commands
complete the tested paths. Payload-property corruption and broker-state cleanup
are fixed and replayed with independent native controls. Session/fixed/command
profiles each use two containers at 1,408 MiB/1.25 CPUs; discovery uses three at
2,048 MiB/1.5 CPUs. Complete native snapshots, source-current hashes and exact
teardown pass. Timed-out combined fixtures remain separately recorded. Current
registration covers 200 sources, with 305 documented hints pending.

The [Jetty file-read checkpoint](VERIFICATION-20261111-jetty.md) advances coverage
to **199 modules, 151 profiles and 1,617 examples**. Six genuine affected/fixed
Jetty releases and unrelated Apache pass 56 cases, 98 module calls and 26 exact
file-loot comparisons. Native pre/post controls make 290 HTTP requests and verify
actual file/process state. Confirmed selected-CVE and fixed-boundary defects are
fixed in a separate worktree and replayed; fixture-option and endpoint-control
errors remain separately recorded. Every profile uses two containers, at most
1,024 MiB/1.25 CPUs, and complete exact teardown leaves Docker empty. Current
registration covers 201 sources, with 304 documented hints pending.

The [Listmonk checkpoint](VERIFICATION-20261111-listmonk.md) advances coverage to
**200 modules, 154 profiles and 1,641 examples**. Three genuine affected/fixed
releases pass 24 cases, 45 module calls and 12 exact loot checks, with 150 native
HTTP controls and unchanged database/process content. A confirmed auxiliary
check error contract is fixed in a separate worktree and replayed; fixture
errors and read-only permission limits remain explicitly recorded. Each serial
profile uses three containers capped at 1,088 MiB/1.45 CPUs. All 24 exact cleanup
queries pass and Docker is empty. Registration covers 202 sources, with 303
documented container hints still pending review.
