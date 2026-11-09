# Grafana traversal release boundaries

The selected checkpoint covers **126 runtime modules, 60 families and 832
functional cases**, adding one module and twenty-three cases to the
[RabbitMQ/Erlang checkpoint](VERIFICATION-20261109-rabbitmq-erlang.md). Every
selected profile has exact expected counts, zero failures/pending/outside errors,
current recorded input hashes and owned teardown. The broader goal remains
active. No PR was created or full local RSpec suite run.

## Genuine release pairs and file collection

The [managed lab](grafana_traversal/README.md) pins official Grafana images on
Linux amd64: 8.0.6/8.0.7, 8.1.7/8.1.8, 8.2.6/8.2.7 and 8.3.0/8.3.1. A genuine
8.3.0 subpath installation and ordinary Apache cover path handling and unrelated
software. No application handler or reply is replaced. Targets expose only
random loopback ports and mount public proof text read-only.

Eighteen native commands and forty HTTP requests independently verify actual
versions, API health, normal admin authentication refusal, exact file bytes,
affected disclosure and fixed-release HTTP 404. Missing plugin/file and
insufficient depth are native negatives. The final native script exits zero
with empty stderr; every command exits zero. A separate early preparation passes
with JSON encoding warnings, corrected by explicit valid UTF-8 encoding before
canonical runs. Actual image inspection verifies Linux amd64.

Twenty-three final cases perform ten public checks and twenty-two scan runs.
Repeated affected/subpath collection produces ten loot files matching every
public proof byte, including Unicode and newlines. Fixed/missing/unrelated runs
produce none. Fixed releases must also print the explicit safe result, with no
unrelated error lines. Positive cases retain the strict failure-banner guard.

## Setup failures and confirmed module defects

| Canonical run | Cases/failures | RSpec seconds | Classification |
| --- | --- | --- | --- |
| `20261109T232206-b77e59` | 23/23 | 91.138109 | Host-only wordlist paths fail option validation |
| `20261109T232714-27d3e7` | 23/23 | 120.996929 | Initial console prompt timeout; no module execution |
| `20261109T233131-b652cc` | 23/9 | 108.147973 | Real original-module checks/collection |
| `20261109T234057-294374` | 23/0 | 114.221944 | Repaired module and stricter fixed-negative assertions |

The first run passes native controls, but every module attempt stops before its
entry point at PLUGINS_FILE validation. The harness now uses canonical container
source paths. The next attempt reaches no BOOT/native/module execution before
the existing 120-second prompt bound; the process remains alive and is not
OOM-killed. No exact cause is claimed. A retry with unchanged corrected inputs
and timeout succeeds after competing heavy setup work is held. All four runs
have zero pending/outside errors and passing owned teardown.

The real original run exposes two defects. Nine standalone checks return
Unsupported because the module implements `check` instead of the scanner's
`check_host` interface. Its collection path retrieves correct bytes from
affected services and no bytes from fixed services, but labels all four fixed
releases vulnerable twice each despite their independently observed HTTP 404.

Separate owning commits implement the standard scanner check interface and use
exclusive fixed-release upper bounds. Public `check` remains the Framework entry
point; scan execution invokes the per-host method. No shared helper changes.
Focused actual version projections reproduce the range decisions without
pretending reduced fragments are complete native HTML pages.

The initial focused suite is **17/4**; adding the advertisement assertion gives
a stable original **18/5**. API repair gives **18/4** and a minimal interface
suite **8/0**. Final **18/0** contains eleven owning and seven shared examples.
One earlier eighteen-case attempt overlaps a source edit during startup and
loads the interface repair; its 18/4 counters are excluded from original-source
comparisons. The stable original rerun holds exact original bytes to completion.

Three spec/native Ruby files lint clean. Production offenses decrease three to
two, both inherited: duplicate RPORT registration and redundant output prefix.
Module tidy retains exit 2 for those existing offenses. Documentation checks
pass after replacing the old inline setup fence and adding the lab link.
All three historical console blocks remain byte-identical; Scenarios content
only gains a terminal newline. Exact scoped comparison corrects an initial
fence-audit regex that consumed pre-scenario Markdown.

## Integrity, cleanup and limits

Every original input set is copied and hash-verified before source repair.
The executed-original and final sets each contain the same 34 keys; only owning
source and acceptance spec differ. The latter strengthens expected fixed-negative
behavior by requiring the safe message and allowing only its existing refusal
banner. Native target/assertion files are unchanged. All final hashes match
current source; no shared runner, dependency or timeout changes were needed.

All four runner projects independently audit absent with zero recorded volumes,
as does the native prototype. Reusable image cache remains. The durable
`grafana-module-validation-20261109-76fe69f2f04` export retains every failed and
passing run, hidden metadata, exact earlier/final sources, native controls,
focused comparisons and three commits. All **452** checksum entries are
independently reread; manifest SHA-256:
`88287e9637ecc60912b66801762c6c625f30f059262442a0667cd2b1e2504463`.

Beta/preview builds, other releases, authentication proxies and other deployments
or platforms remain unqualified. No session claim is made. Declared hashes are
not the full dependency graph. Aggregate selection is
`tmp/module-target-checkpoint-grafana-current.json`; WordPress admin remains
unqualified. Solr, Prometheus and ActiveMQ continue separately. Fork CI remains
separate from these runtime results; the preceding pushed checkpoint's ten
workflows are queued at the latest inspection, with no overall green claim.
