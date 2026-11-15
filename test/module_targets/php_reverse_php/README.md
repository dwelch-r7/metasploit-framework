# Native PHP reverse-shell regression

This component tests the selectable `php/reverse_php` payload's generated PHP
through real loopback TCP connections. It adds **38 functional contracts**, not
a new exploit/scanner owner qualification. It uses one capped PHP container and
the host repository's installed Ruby/Bundle; no Framework container, handler or
console is started. WordPress and Drupal session profiles cover application and
Framework session integration separately.

From the repository root, with dependencies already installed:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb php_reverse_php
```

The guarded runner owns the shared lock, empty global-container prerequisite,
resolved service-count check, build, runtime JSON, logs, source hashes and owned
teardown. The component uses `console: false` and no published ports. Its PHP
server/client connections stay on the container's loopback with `network_mode:
none`. The container has 0.5 CPU, 192 MiB, 64 PIDs, init, user 33, no capabilities,
no privilege escalation and a read-only root. Only bounded tmpfs directories are
writable. A tmpfs override prevents the inherited WordPress image volume from
allocating an anonymous volume. No host bind mounts are needed.

The exact digest-pinned WordPress PHP 8.3.28 base bundles matching PHP source and
build tools. The Dockerfile compiles only `sockets` with one compiler job; it adds
no OS packages or project dependencies. The copied controller, case table and
command `0` executable remain read-only at runtime. Build logs retain source and
extension hashes; runtime evidence records the PHP binary, extension capability,
controller/source identities and OOM/PID counters before and after, when readable.
`memory.events:max` is informational; OOM counters and `pids.events:max` must be
zero when available. Missing cgroup-v2 files are recorded as unavailable.

Before the suite, host Ruby includes the actual payload source in `Msf::Payload`
and calls its public `generate` API under Bundle. It saves those exact bytes,
then passes them and their hashes to the controller as JSON stdin. Generated PHP
runs in a separate PHP interpreter for each conversation. The controller records
exact input/output bytes, disabled functions, socket fallback banner, exit status
and child reaping. There are no TCP or interpreter doubles.

`cases.json` preserves the independently verified 38-case matrix: both socket
transports, each of the six execution helpers, newline/whitespace/empty probes,
ordinary and Unicode output, spacing, compound commands, literal command `0`,
`cd`, exit, quit and EOF. Generation seed 7721 keeps the captured default helper
order, whose first method is `exec`. Its trailing-output-whitespace normalization
is checked exactly; other helpers retain those spaces. A changed helper order
is an explicit fixture prerequisite failure, not a broadened output matcher.

RSpec reports each conversation independently from one captured matrix. Aggregate
generation/image/source/count failures are suite-level infrastructure errors,
not 38 copies of a before-context failure. Postflight resource errors are also
separate from the per-case results. All examples carry `acceptance: true`; default
CI excludes them and performs no native capture. `acceptance_spec_helper` also
loads seven existing untagged support examples: those are not native payload
coverage. The guarded runner supplies `--tag acceptance`, giving exactly 38 cases.

For an explicit before/after regression, provide a trusted original payload Ruby
source file without modifying the production checkout:

```sh
PHP_REVERSE_TARGET_SOURCE=/absolute/path/to/original_reverse_php.rb DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb php_reverse_php
```

The override and effective source hash are recorded. An override run does not
qualify the current checkout. The verified pre-fix source SHA256
`380c135cefcd5d64fc3c0d429bd7af2729af08ee7f6f5952dc61be1d012c0d1c`
produces eight empty-command `ValueError` failures across `fsockopen` and the
genuine disabled-`fsockopen` socket fallback. Its other 30 controls pass. The fixed
payload is expected to pass all 38, including the next ordinary command after a
blank probe. This target does not diagnose the separate staged PHP Meterpreter
bootstrap investigation, and does not claim PHP 5.6 or IPv6 native coverage.

No human module Scenarios are generated or changed. See the
[shared target guide](../README.md) for result interpretation and teardown rules.
