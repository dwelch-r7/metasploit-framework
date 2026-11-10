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
The [current integrated checkpoint](VERIFICATION-20261110-grafana-expression.md) records
**177 runtime modules, 115 qualified families and 1,393 functional cases**.
Grafana SQL expressions pass fourteen cases with four used owning Bash sessions,
two separate native payload calibrations and exact quoted UTF-8 output. The
module-local byte-encoding repair preserves request bytes and corrects their
declared length; session dispatch/transfer failures remain separate fixtures.
Parent 82 current inputs, all 233 imported files, 362 export entries, lint/docs
and 29 cleanup queries pass. Positive RCE scope is 11.0.0; 11.0.5 RCE,
other release branches and additional delivery/platform paths remain pending.
The full campaign remains incomplete while feasible, valuable modules await review
or functional verification.
See [deferred investigations](DEFERRED.md) for retained failures that remain
unqualified after bounded investigation.
