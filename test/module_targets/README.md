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
bundle exec ruby tools/dev/run_module_target_tests.rb --list
bundle exec ruby tools/dev/run_module_target_tests.rb redis
bundle exec ruby tools/dev/run_module_target_tests.rb --all
```

The runner currently runs on Linux or macOS with a local Docker Engine. It
creates a fresh, uniquely named Compose project for each family,
waits for health checks, discovers random host loopback ports, runs its acceptance
spec, and removes its containers, networks and volumes. It uses an isolated
Framework configuration directory. It does not require a Framework database.
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
The [current qualification record](VERIFICATION-20261109-jenkins-udp.md) records
**94 runtime modules, 36 families and 498 functional cases**, including the
subsequent Jenkins, TFTP, NTP, Jenkins-command and Elasticsearch profiles.
All recorded inputs are current, exact counts match and owned cleanup passes.
The full campaign remains incomplete while feasible, valuable modules await review
or functional verification.
