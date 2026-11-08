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

## Layout and contribution contract

- `test/module_targets/<family>/compose.yaml`: real targets, configuration,
  health checks and optional source-built images. Pin versions and image digests.
- `test/module_targets/<family>/manifest.yml`: acceptance spec path, expected
  example count, module fullnames and service ports. Several modules may share
  one target family. `connection_env` maps services to an existing protocol
  suite's environment-variable prefix, avoiding duplicate suites.
- `spec/acceptance/module_targets/<family>_spec.rb`: short functional cases,
  independent target validation and assertions on meaningful results.
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
privileged containers, Docker socket mounts and host mounts except read-only lab
configuration. Container breakout, kernel, hardware and licensed targets need
individual feasibility assessment; a service container does not model a complete
operating system. Keep uncertain modules in the review queue.

## Campaign queue

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
The full campaign remains incomplete while feasible, valuable modules await review
or functional verification.
