# Langflow custom-component execution — 2026-11-14

All **17 functional examples and 34 public module calls pass**, with four exact
command proofs and six complete session lifecycles. The campaign reaches
**235 modules qualified in covered paths, 279 profiles and 2,666 functional
examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_custom langflow_custom_disabled
```

| Genuine configuration | Cases / public calls | Commands / sessions |
| --- | ---: | ---: |
| Custom components enabled | 10 / 20 | 4 / 6 |
| Custom components disabled | 7 / 14 | 0 / 0 |

The [lab guide](langflow_custom/README.md) and
[vendor record](langflow_custom/vendor.json) pin the official Linux amd64 image
by digest. Actual installed versions are Langflow 1.10.0, langflow-base 0.10.0,
lfx 1.10.0, MCP 1.27.2 and Python 3.14.5, running as UID 1000/GID 0. The tests
verify four installed endpoint/settings/loader source hashes. The image's
observed source is authoritative; it differs from the raw GitHub source found
under the same release name. No replacement endpoint or external AI provider
is used.

## What is qualified

This result qualifies the direct authenticated custom-component execution path
in `exploit/multi/http/langflow_auth_rce_cve_2026_18729`, including repeat runs,
sessions and cleanup. The enabled profile permits custom code. The disabled
profile proves that `LANGFLOW_ALLOW_CUSTOM_COMPONENTS=false` rejects it with
HTTP 403 before execution. The version-only check still returns `Appears`.

The [vendor advisory](https://www.ibm.com/support/pages/node/7284733) describes
broader code-execution policy bypasses. These tests do **not** establish those
other paths or prove that this direct endpoint bypasses the disabled policy.
That distinction remains an explicit investigation limit for the owner and
its CVE attribution.

## Confirmed defects and fixes

The real backend evaluates an ordinary class body six times per request. The
owner's original module-local `_fired` guard still executes its decorator
payload three times across fresh compilation contexts. Independent native
append canaries reproduce both counts twice. A public Framework invocation
then appends the exact command marker three times and leaves an exited child
in the persistent backend. This is a source defect, not a presumed lab failure.

The corrected owner atomically claims a randomized, non-identifier key in the
backend builtin namespace. It cannot shadow a normal builtin name, and it
survives the repeated fresh compilation contexts without hardcoding a count.
Only the winner starts a daemon thread running a waited Python subprocess.
The payload stays out of the backend interpreter, permits an HTTP response,
and preserves both Meterpreter fork settings. The generated output method also
returns valid Data instead of referencing the undefined `_out` placeholder.

Cleanup removes only that attempt's key through an inert component and always
calls parent cleanup. Pending records retain their original bearer token and
HTTP origin, including host, port, TLS, virtual host, base URI and proxies.
Changed origins are skipped rather than receiving an old token. Failed cleanup
remains available for retry.

Both emitted components include an attempt-specific response prefix and backend
PID. A guard is retired locally only after a successful cleanup response with
matching proof. Missing, malformed or mismatched proof is reported and retained;
missing primary metadata does not turn an otherwise successful request into a
failure. This is tested on the single-worker deployment; it is not a routing
guarantee for load-balanced replicas or separate PID namespaces.

## Real execution and state evidence

Run `20261114T044645-90451a` completes in approximately **4 minutes 53 seconds**,
including a fresh cold console, both serial deployments, native controls and
teardown. The original controller, manager and independent observer all exit
zero. Live caps and the actual first cold BOOT/prompt and fresh metadata are
observed directly. The second profile uses only the normal same-invocation
metadata seed, whose bytes are compared independently.

Every case repeats without another `use`. The enabled profile verifies version
classification, bad credentials with AutoCheck on/off, exact command execution
with AutoCheck on/off, Python shell, forked/nonforked staged Python Meterpreter,
missing paths and refused ports. Each command produces exactly one marker.
All six sessions reach a real ready event, perform remote operations, create
exact UID 1000 file bytes, match exploit/payload database provenance and close
their database rows. A native version request succeeds while each is open.

Shutdown requires the exact remote PID/birth identity to disappear. The complete
original target process set is restored, with no extra live or defunct child,
callback connection, Framework job or session. Controlled files are removed.
The disabled profile repeats the check/authentication/connection cases and
rejects execution with AutoCheck on/off, without files or sessions.

An authenticated native canary snapshots the actual backend's complete builtin
keyset and PID through the custom-component API, writing and removing a
controlled JSON file. A standalone Python process would inspect a different
namespace and could not prove this cleanup. The enabled backend's **159 builtin
keys** and PID match before and after all public executions. No guard-removal
or worker-proof warning occurs in that profile. Native flow registries and all
other before/after fields match in both profiles; all ten native invocations
exit zero.

Login rate limiting remains enabled. These automated profiles use the supported
`LANGFLOW_RATE_LIMIT_PER_MINUTE=100` allowance to keep repeated positive and
negative cases quick. Native controls verify the effective setting and perform
six consecutive valid logins from the same client, beyond the default allowance.
The default five-attempt budget was separately exhausted in an earlier real
run; its evidence is retained below. The complete burst is not qualified under
that production default.

Three containers run at a time: target 3,072 MiB/one CPU, Framework 768 MiB/one
CPU and PostgreSQL 128 MiB/0.2 CPU. Swap equals memory, privileged mode is
disabled, and published ports bind to localhost. OOM, OOM-kill and PID-limit
counters remain zero. All **16 independent teardown queries** pass for six
exact container IDs, two networks, project labels and global inventories.
No application volume is created. Five subsequent global container inventories
are empty, and the shared heavy-lane lock is free.

## Verification and preserved failures

The source's final focused run passes **13 owner examples plus seven existing
formatting examples**. Same-spec comparisons reproduce duplicate/blocking
execution and the missing worker-proof behavior before their fixes. The Python
model exercises actual generated code with repeated fresh compilation scopes,+a held loopback callback, a separate child, transport EOF, child reaping and
guard removal. HTTP and Langflow classes are explicit doubles; the real
container cases provide the application/session evidence.

Strict Ruby lint, module tidy, documentation tidy, Python syntax and filtered
discovery pass. Discovery runs seven shared examples without a lab environment
or load errors. No full RSpec suite is run. Shared execution assertions are
extracted for reuse; the previous validation owner is replayed separately and
passes all ten cases, twenty calls and six lifecycles. Its 54 tested input
hashes remain unchanged after that replay.

Earlier evidence distinguishes setup, native observations and source failures:

- Langflow 1.8.4 evaluates the class body six times, contradicting the initial
  one-write oracle. Its installed packages do not implement the tested custom
  policy setting; it is not used to claim the 1.10.0 policy behavior.
- A protected 1.10.0 probe wrongly expects benign custom code to be accepted;
  its actual 403 response is correct enforcement. No owner is called.
- `langflow-custom110-public-duplicate-failure-20261114` preserves the original
  public triple-execution failure and the successful older-owner replay:
  211 files, 62 inputs, manifest
  `8ae43c04fbcc86ad0d13e8248bfa9c4bf18786fa595ead7811ac6c57f80a37e4`.
- `langflow-custom110-default-login-limit-20261114` preserves the first fixed
  source run: one exact command and cleanup pass, then the default five-login
  budget rejects later correct credentials after four negative attempts and
  one valid attempt. Both native before/after controls still match; target
  logs record rate-limit exceptions. This is a fixture budget failure, not a
  regression in the source fix. Its 266-file/58-input manifest is
  `a283fbe7e1ac68cc25ec79817fa6bd3a3e8a93eb1acbb3ef5af17a5c1283c61d`.
- Initial local socket/test-double and lint setup failures remain separate
  from the corrected identical-spec regression comparisons.

Each owned failed run finishes teardown and an independent audit before its
selected inputs change.

## Evidence and publication inputs

The immutable archive
`/Users/dwelch/.codex/reports/langflow-custom110-qualified-20261114` contains
**280 files and 58 selected inputs**, independently copied without hardlinks
and hash-verified. Its `MANIFEST.sha256` hash is
`2a990b885e66e4a474a94a06e1ecef58a4d0558c6665693a8c8f4154e57d6afb`.
After sealing, one duplicated README word and paragraph wrapping are corrected;
that prose-only byte delta is recorded separately. All implementation inputs
remain identical; the functional suite is not replayed for that prose change.

Source commits are `e8b6482d5374fd43b54094027e098d466e86e3df` and
`0acc1eed377ad5d9ac51691319755981f112607b`. Shared assertions are committed as
`9507fd6dc20d703b80f88086f63bb727bd857eaf`; fixture commit is
`7f41352ed587448616f489f26c2f9b12487b26bf`. Final owner SHA-256 is
`ba122244fc45cb7e6fab1142bd2b4109fbbdc5328ca994cdff774b3e2434a9f9`.
The module guide's original `## Scenarios` through EOF is byte-for-byte unchanged,
SHA-256 `adeadff0d357bf3c13ce0f1b6eacdf81fc4f3d879a8df93b968dd0849d425e30`.

## Self-review and remaining scope

**Summary:** Conditional authenticated execution, single payload delivery,
both session families, both Meterpreter fork modes, repeat runs and state
restoration qualify in the enabled profile; the disabled profile rejects them.

**What looks good:** Independent native controls, exact append proofs, actual
backend namespace comparison, worker response checks, origin-bound cleanup,
complete session/database/PID closure, untouched human Scenarios and bounded
serial resource use.

**Concerns:** Other versions, architectures, operating systems, worker
topologies, load-balanced replicas, TLS, path prefixes, authentication roles
and transports remain unverified. The broader advisory policy-bypass/CVE path
is not established by this direct-endpoint result. No further material finding
remains in the tested single-worker scope.

**Suggestions:** Independently calibrate the remaining Langflow owners,
including their disabled-policy prerequisites. Inventory is 5,179 source files,
237 registered owners, 268 pending documented container hints and zero stale
reviews. The standing `druid_js`, `freeswitch_batch`, `superset_rce_owner` and
`wordpress_admin` deferrals remain unchanged. The older remote Mettle
`post/test/file` timeout still has an unverified cause.
