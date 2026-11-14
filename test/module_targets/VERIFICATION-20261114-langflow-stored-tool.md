# Langflow stored-tool public execution — 2026-11-14

All **44 unique functional examples and 94 public module calls pass**, with twelve
exact credential-created command proofs and 24 complete session lifecycles.
The campaign reaches **243 modules qualified in covered paths, 298 profiles and
2,842 functional examples**. The broader goal remains incomplete. No PR is created.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow_stored_tool_legacy langflow_stored_tool langflow_stored_tool_fixed
```

The [lab guide](langflow_stored_tool/README.md),
[affected recipe](langflow_stored_tool/compose.yaml),
[legacy recipe](langflow_stored_tool_legacy/compose.yaml),
[fixed recipe](langflow_stored_tool_fixed/compose.yaml) and
[vendor record](langflow_stored_tool/vendor.json) exercise
`exploit/multi/http/langflow_unauth_rce_cve_2026_10134` against genuine official
Linux amd64 images pinned by digest. Normal API access requires application
login. Public build requests use no authentication token. No endpoint or
application implementation is replaced, and no model/provider is required.

| Genuine configuration | Examples / public calls | Exact commands / sessions |
| --- | ---: | ---: |
| 1.8.4, credential creation and existing public flows | 17 / 36 | 6 / 12 |
| 1.9.0, credential creation and existing public flows | 17 / 36 | 6 / 12 |
| 1.10.0, guarded public stored-tool execution | 10 / 22 | 0 / 0 |

## Independent calibration and original failure

The [vendor advisory](https://www.ibm.com/support/pages/security-bulletin-unauthenticated-server-side-rce-pythoncodestructuredtool-public-flows)
and [CNA record](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/10xxx/CVE-2026-10134.json)
identify the stored legacy tool-code execution path and recommend 1.10.0.
Installed-source capture verifies 43/44/43 source hashes across the three images,
including routing, authentication, flow identity, build events, graph execution
and component code. The vendor range is 1.0.0 through 1.9.3; the functional
result qualifies only the representative versions/configurations above.

Seven independent native controls per release establish working applications
before Framework execution. Missing cookies return 400, private and unknown
public-route UUIDs return 403, and authenticated private stored-code builds
execute twice on every release. Public stored-code builds execute twice on
1.8.4/1.9.0 and return 400 without execution on 1.10.0. Successful native jobs
reach a finite end and valid vertex, write the exact one-record UID 1000/GID 0
canary, and restore the complete original flow registry. Login is required and
component loading is eager. Custom-code settings are enabled where supported;
1.10.0 retains rate limiting with a fixture quota of 100/minute.

Langflow 1.10.0 removed `PythonCodeStructuredTool`. Its migration control compiles
the exact unmodified 1.9.0 legacy source through the supported authenticated
component API, with the upstream MIT license preserved alongside the fixture.
Private authenticated execution distinguishes the public type guard from broken
legacy code. This does not claim the component remains installed in 1.10.0.

The unchanged module's diagnostic replay has three examples, one failure and
five calls. Its credential-created command writes the exact marker once, but
backend-owned zombie PID 418/PPID 41/birth 9066406/UID 1000 persists across twenty
observations. The genuine public job nevertheless reaches a valid Tool vertex
and finite end. Its actual `result_tool` output is type `unknown` with an empty
message. No serialized Tool/Data nonce is invented as a delivery oracle.
Both existing-UUID calls trigger stored canaries while selected command markers
remain absent. The original native before/after results match, fixture flows
are deleted back to the original registry, and all eight teardown queries pass.
Broad session and error coverage was not reached by that diagnostic run.

An earlier native canary failed because the legacy string input normalized
escaped newlines inside a nested quoted `exec` expression. That fixture failure
was sealed before replacing it with a direct one-line decorator expression.
Submitted/stored AST validity alone did not establish the backend's effective
input. It is not classified as a module defect.

## Corrections and final verification

Credential-created payloads now run in separate Python interpreters with
DEVNULL streams. A daemon worker waits for and reaps each interpreter, while
a component-local guard prevents repeated preparation from duplicating execution.
Base64 transport is retained for the legacy input normalization behavior.
The genuine StructuredTool callable returns an empty string instead of an
unbound variable. Payload globals and backend descriptors remain isolated.

The owner follows the real returned job through bounded event polling. Created
flows require finite completion, a valid vertex with the fresh node identity,
and the actual unknown/empty Tool output. This confirms component completion;
commands and sessions are proved independently. Malformed, failed and unfinished
jobs produce explicit failures. HTTP 401/403 produce NoAccess, other unexpected
statuses produce UnexpectedReply, and expected transport failures produce
Unreachable. Version checks handle malformed metadata and expected transport
errors without raising.

Only module-created flows enter the cleanup ledger, with their original token
and target origin. Cleanup follows known unfinished jobs before deleting stored
code, retains uncertain submissions/failed removals for follow-up, preserves
existing flows and always calls parent cleanup. Unknown submission replies and
ambiguous HTTP 500 responses intentionally retain their flows because completion
cannot be established. BuildTimeout bounds each polling window; a request can
use its own HttpClientTimeout, and cleanup may use a second polling window.
Those uncertain/error paths have focused doubled coverage, not live failure
injection qualification.

`FLOW_UUID` is explicitly trigger-only: it does not upload the selected payload.
Eight final stored-canary proofs require selected command markers to remain
absent. Twelve credential-created sessions and twelve existing-flow sessions
pass. The latter use six separately prepared public flows containing matching,
genuine Framework-generated Python payloads. Preparation is an independent
fixture prerequisite, not arbitrary payload delivery by the UUID mode. Those
flows are separately retired after their repeated session tests.

Affected profiles cover normal and AutoCheck-disabled commands, Python shells,
staged Meterpreter with both fork settings, incorrect credentials, private and
unknown UUIDs, refused ports, missing prefixes and repeated credential-to-public
mode transitions. Every path repeats through the normal console. Framework
creates executing replicants; selected-module reuse does not establish reuse
of a single executing Ruby object. The focused unit suite labels its direct
same-object mode-transition test separately.

Every session has live remote identity/file proof, correct module/payload
provenance in Framework and the database, responsive backend health, graceful
shutdown, and disappearance of its exact PID/birth identity. Every case restores
jobs, sessions, connections, process identities and complete native flow records.
No zombie or extra-process allowance is used. No transient observations require
an exception in the final accepted runs. Fixture flows are deleted back to the
original registry, and cgroup OOM/PID counters remain zero.

The fixed profile verifies Safe/normal AutoCheck, ForceExploit and disabled
AutoCheck, command absence, shell/Meterpreter handler closure, public/private
UUIDs and mode transitions. Fourteen calls must fail specifically with HTTP 400
while triggering the public tool flow. Generic creation/login/server failure
cannot satisfy that oracle. The permanent operation/status assertions were
strengthened after the initial passing three-profile run and replayed from a
fresh cold console: all ten cases and 22 calls pass again. These repeats add
no unique examples or profiles to the campaign totals.

The identical focused 48-example suite, seed 10134, returns 40 failed expectations
on the original and zero on the fix, with zero outside-example errors. These
are changed-behavior expectations, not forty separate defects. Both local emitted
Python probes exit zero; the fixed probe returns while callbacks are held,
executes one matching separate child despite repeated preparation, uses DEVNULL
without inheriting an explicitly inheritable backend socket, preserves backend
builtins and reaps both attempts. HTTP, LFX/Tool/Pydantic context and reporting
are disclosed doubles. The genuine application acceptance supplies the missing
runtime/session evidence.

Strict RuboCop, module/docs tidy, Ruby/Python syntax and diff checks pass.
The source fix was independently verified and cherry-picked from worker commit
`79e893f5f23139e3b2b4f7c6c11a3eee9e25bffb` as `f91a00be814`.
The historical human module-guide Scenarios remain byte-identical.

## Resources, evidence and remaining scope

At most three capped containers run together: target 3,072 MiB/one CPU,
Framework 768 MiB/one CPU and database 128 MiB/0.2 CPU. Swap equals memory,
PID caps are live-verified, and published ports bind to localhost. Profiles
run sequentially under the shared worktree lock. The initial invocation starts
cold and reuses only its own ordinary metadata seed; the stronger fixed-only
replay starts cold again. Live prompts, cache provenance and caps are checked
independently.

All 24 exact-resource/project/global teardown queries for the final selected
profiles pass. The superseded initial fixed execution has another eight passing
queries. Five final inventories are empty and the shared lock is free. No
unrelated containers remain. No images or unrelated volumes are pruned.

Read-only local archives retain full raw output, selected inputs, process exits
and independently verified manifests:

| Evidence | Location | Manifest SHA-256 |
| --- | --- | --- |
| Native calibration | `~/.codex/reports/langflow-10134-native-calibration-20261114` | `77756220ccd993ed050cc48958a910371d36c7d3bed34609dd10c3ea8c5a1646` |
| Original failure | `~/.codex/reports/langflow-10134-public-original-failure-20261114` | `8ff3e687e4580ba49637d1b49392a51eb005c551dfe0fbfece1f2c30fb60544f` |
| Initial three-profile pass | `~/.codex/reports/langflow-10134-three-profile-acceptance-20261114` | `7bf2877ce05833abc18496eda1353feb14eff522b002703f7ec535690a2a98e8` |
| Final matching selected inputs | `~/.codex/reports/langflow-10134-qualified-20261114` | `8053f50d5a1693c48917daa2237559a23f2f42127aafa83ef743513378b2da63` |

The final archive contains 536 files and 68 selected inputs, with no hardlinks;
all files/directories are read-only and every manifest entry is rehashed.
It selects the two affected profiles from run `20261114T120805-1b1c22` and the
stronger fixed profile from `20261114T122049-b6288b`. Module source SHA-256:
`faa1d877cb64e6327854a240a0309743cd9c2cc2caeae4b68c8b068381440e07`.
Preserved Scenarios SHA-256:
`37b01f0a26fed2b68fa1b46d19381f62434939763c3c355eb617b21c2b33b7df`.

Static inventory: 5,179 source files, 245 registered owners, 22 individual reviews,
zero stale reviews and 256 pending documented-container reviews. Registration
is not qualification. Remaining versions, execution paths and campaign targets
remain unqualified. Standing path deferrals include `druid_js`,
`freeswitch_batch`, `superset_rce_owner` and `wordpress_admin`; the earlier remote
Mettle `post/test/file` timeout still has unverified cause.

**Summary:** The covered credential-created payload and existing stored-code
trigger lifecycles pass against genuine affected targets; the fixed public guard
is explicitly verified. **What looks good:** Repeat commands, session/fork paths,
finite jobs and complete state/resource restoration have independent evidence.
**Concerns:** UUID mode requires pre-existing suitable code; uncertain job
submissions preserve flows for manual follow-up. Broader versions and campaign
coverage remain incomplete. **Suggestions:** Continue the remaining feasible
module queue and keep these limits attached to this result.
