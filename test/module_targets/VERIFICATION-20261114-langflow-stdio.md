# Langflow MCP stdio execution — 2026-11-14

All **17 functional examples and 34 public module calls pass**, with four exact
command proofs and six complete session lifecycles. The campaign reaches
**237 modules qualified in covered paths, 283 profiles and 2,703 functional
examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_stdio langflow_stdio_fixed
```

| Genuine configuration | Cases / calls | Commands / sessions |
| --- | ---: | ---: |
| Langflow 1.8.4, active non-admin user | 10 / 20 | 4 / 6 |
| Langflow 1.9.0, active non-admin user | 7 / 14 | 0 / 0 |

The [lab guide](langflow_stdio/README.md), [Compose fixture](langflow_stdio/compose.yaml)
and [vendor record](langflow_stdio/vendor.json) pin official Linux amd64 images
by digest. The 1.8.4 image contains langflow-base 0.8.4, lfx 0.3.4, MCP 1.26.0
and Python 3.12.12; 1.9.0 contains langflow-base 0.9.0, lfx 0.4.0, MCP 1.27.0
and Python 3.12.13. Both run as UID 1000/GID 0 with automatic login disabled.
Eight installed endpoint, validation, transport, settings and startup source
hashes are verified. No application endpoint or implementation is replaced.

## Independent setup and scope

Native setup creates an active account and verifies `is_superuser=false` using
its real token. The module uses that account. An SDK-based stdio server exposes
one real echo tool. Independent SDK initialization, listing and a tool call
validate its source; both backend versions also discover its tool through the
actual MCP API. Read-only mounts provide this control and the process observer.

Explicit control definitions are seeded in both the superuser's and ordinary
user's MCP registries. Every public operation must preserve their complete
configurations. Automatic project-to-MCP registration is disabled with the
supported `LANGFLOW_ADD_PROJECTS_TO_MCP_SERVERS=false` setting, whose effective
Settings value is verified. This keeps the fixture independent of optional,
delayed starter-project catalog changes. The stdio registration and discovery
paths remain genuine.

On 1.8.4, independent encoded canaries are absent after registration and execute
once per tool-count listing. Repeating that listing executes the same saved
canary again. Each temporary definition and file is removed. On 1.9.0, the
legitimate SDK server works while a minimal `python3 -c pass` configuration and
two independently encoded canaries are rejected with 422 and no command effect.
These controls run before and after the public-module tests.

Qualification covers the implemented REST registration/listing path in
`exploit/multi/http/langflow_auth_command_injection_cve_2026_93674`. The
[REST advisory](https://github.com/langflow-ai/langflow/security/advisories/GHSA-7w94-79vh-5mr2)
and [broader MCP advisory](https://github.com/langflow-ai/langflow/security/advisories/GHSA-w794-rj3p-xv45)
distinguish the 1.9.0 REST model restrictions from later execution-sink
hardening. These tests do not establish that all MCP execution surfaces are
safe on 1.9.0, or resolve the broader CVE attribution and version range in the
[IBM bulletin](https://www.ibm.com/support/pages/node/7290694).

## Confirmed defects and fixes

The unmodified owner executes one exact command as the ordinary user, then
leaves its inline payload registered as an MCP server. The original run stops
after four cases and seven public calls, with one example failure and one
cleanup verification error. The native control definitions are unchanged and
the original process set is restored. The stray definition contains that
invocation's payload. Native controls independently prove that saved definitions
execute again during later discovery; the leftover entry is a real repeat-run
hazard rather than a presumed setup problem.

A separate unmodified 1.9.0 run passes all native controls before and after but
produces two failures in seven cases: `check` incorrectly returns `Appears`, and
AutoCheck proceeds to an API rejection. Twelve public calls complete without
command effects or registry changes. The corrected passive check excludes
1.9.0 from this implemented route and returns `Safe` there.

Cleanup now retains each attempted definition's name, exact configuration,
original token and HTTP origin. Successful saves and transport-uncertain saves
can be recovered. Explicit rejected creates, including a name collision, do not
confer ownership. Cleanup retrieves the named definition and deletes it only
when the configuration matches; changed definitions or targets are preserved,
and failed cleanup remains available for retry. Parent cleanup always runs.
The vendor API provides no conditional deletion, so GET identity confirmation
and DELETE cannot be atomic against a concurrent edit.

## Genuine execution and lifecycle evidence

Run `20261114T063419-a39bb5` completes in approximately **5 minutes 37 seconds**,
including a fresh cold console, two serial deployments and teardown. The
original controller, manager and independent observer all exit zero. The actual
first BOOT, prompt and fresh metadata are observed independently. The second
console uses only the normal same-invocation metadata seed, with matching bytes.

The vulnerable profile repeats version checks, bad credentials with AutoCheck
on/off, exact commands with AutoCheck on/off, Python command shells, staged
Python Meterpreter with forking enabled and disabled, a refused port and a
missing application path. The protected profile repeats passive detection,
AutoCheck rejection, bad credentials, forced execution with AutoCheck disabled
or ForceExploit enabled, and the connection/path negatives. Every case repeats
without another `use`.

Each command appends exactly one marker. All six sessions reach a real ready
event, perform remote identity and file operations, create exact UID 1000 bytes,
match exploit/payload database provenance and close their database rows. Native
version requests succeed while sessions are open. The two nonforked Meterpreter
sessions also remain usable after **22.002 and 22.008 seconds**, beyond the
configured 20-second discovery deadline. Fresh remote operations confirm the
same session, process and reporting row before normal shutdown. Payload delivery
is unchanged; the evidence does not require an additional process wrapper.

Shutdown requires the original remote PID/birth identity to disappear. The
complete initial process set returns, with no extra live or defunct child,
callback connection, Framework job or session. Controlled files are removed.
All **60 native invocations** exit zero, including six live-session health
requests and **50 registry checks**. Full before/after controls match in both
profiles, including user roles, native execution/rejection proofs, source hashes
and both users' registry fingerprints.

Three containers run at a time: target 3,072 MiB/one CPU, Framework 768 MiB/one CPU,
and PostgreSQL 128 MiB/0.2 CPU. Swap equals memory, privileged mode is disabled,
and ports bind to localhost. OOM, OOM-kill and PID-limit counters remain zero.
All **16 independent teardown queries** pass for six exact container IDs, two
networks, project labels and global inventories. Five later inventories are
empty, and the shared lock is free. No application volume is created.

## Verification, failures and evidence

The source fix passes **35 focused owner examples**. Two key regressions fail
against the original source and pass after the fix. An earlier full file run
also includes seven existing support examples. HTTP, payload strings and
generated names are explicit unit-test doubles; real application, SDK and
session evidence comes from the container replays. Strict Ruby lint, module
tidy, documentation tidy, syntax and input-path checks pass. Filtered discovery
passes seven shared examples without a lab environment. No full suite is run.

Setup failures remain separate from module failures. The first native client
incorrectly assumes an empty registry throughout startup; the application adds
a starter MCP entry later. Its corrected default-configuration control preserves
that entry and passes. The first public preflight rejects a legitimate extra
`main_version` field; no module calls run. The next preflight incorrectly requires
an optional starter entry to appear. Both are sealed before correction. The
final explicit catalog configuration and non-admin controls pass independently.

The original registry defect is sealed in
`/Users/dwelch/.codex/reports/langflow-stdio-public-registry-leak-20261114`:
180 files, 56 inputs, manifest
`e64c3db61d94b2da859daf71179e2ebc660c1a6ef39ba9b21ff41316d3aa98cf`.
The original fixed-version classification run is sealed separately in
`/Users/dwelch/.codex/reports/langflow-stdio-public-fixed-classification-20261114`:
189 files, 57 inputs, manifest
`14aeaf67442289574f420de6a8847cfc13b1ec8e59473b30b33d27804ef9cc91`.
Its owned resources are removed, but the first global audit finds unrelated
AWS/GitHub MCP sidecars. They are removed as authorized; a separately sealed
cleanup supplement verifies all eight queries afterward. No image or volume
prune is performed. The final matrix has no such cleanup failure.

The initial shorter-session matrix also passes all 17 cases before the lifespan
check is added. The final immutable archive is
`/Users/dwelch/.codex/reports/langflow-stdio-qualified-20261114`:
**311 files and 59 selected inputs**, independently copied without hardlinks
and hash-verified. Its `MANIFEST.sha256` hash is
`6236158b6c54be841bb228301307465816f232c54db0ce0188a78dda1d0bc789`.

Archived timing logs retain Rex's `[block_result, elapsed_seconds]` pairs. The
parent audit reads the verified duration component. After sealing, the test's
recorder variable is corrected to destructure that pair and log numeric seconds.
This changes one instrumentation line; sleeps, assertions, remote operations,
module code and the other 58 selected inputs are identical. The delta and a
check against the actual stopwatch implementation are recorded separately;
the Docker matrix is not repeated for this recording-only correction.

Source commit is `b91d6f7062a`; shared-helper commit is `c59c0edeb9c` and
fixture commit is `c98fcebfa50`. Final owner SHA-256 is
`4bc5a0d7ddbd6275105d42af3478daebf63e27afd4025c96edc1216281507440`.
The original human `## Scenarios` through EOF is byte-for-byte unchanged,
SHA-256 `babee0f3368da0cff60a348596500cccfbdb75ab2e966913846befe53871a109`.

## Self-review and remaining scope

**Summary:** The registered payload is removed safely, the passive REST boundary
is corrected, and complete repeated execution/session lifecycles pass.

**What looks good:** Independent controls prove non-admin access, API gating,
exact command effects and tenant preservation. Longer same-session proofs avoid
using an opening message alone as evidence.

**Concerns:** Qualification covers these two Linux images and one backend worker.
Other releases, operating systems, MCP surfaces and broader CVE attribution
remain unverified. The API's concurrent-edit deletion race remains bounded by
the identity check. The older remote Mettle `post/test/file` timeout remains
cause-unverified.

**Suggestions:** Continue the remaining feasible-module queue. Inventory records
5,179 source files, 239 registered owners, 266 unreviewed documented container
hints and zero stale reviews. Standing deferrals remain `druid_js`,
`freeswitch_batch`, `superset_rce_owner` and `wordpress_admin`.
