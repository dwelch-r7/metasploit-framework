# n8n workflow expressions and check repairs

Two new native-gated profiles pass **8 examples / 0 failures / 0 pending**.
The real module executes two command payloads, preserves complete unrelated
workflow records and removes its own workflows. Two confirmed check defects
are repaired in an isolated worktree: a false positive on fixed 1.120.4 and a
nil-response exception on a refused port. **Default fetch/Meterpreter delivery
and Windows remain unqualified.** No PR is created; the broader goal stays active.

The nineteen previous stated profiles retain 62 cases and twenty-five used/closed
OS sessions, with all 214 declared inputs unchanged. The latest twenty-one
profiles have **70 qualified cases**, 230 current inputs and 124 zero cgroup
event captures. Historical coverage reaches **324 owners in stated runtime
paths, 691 profiles and 4,845 functional cases**. These counts describe covered
paths, not fully qualified modules or completion of the full inventory.

## Native controls and real defects

Recipes use official pinned Linux amd64 n8n **1.120.0** and **1.120.4** images,
Node **22.21.0**, UID **1000**, default single-process SQLite and the original
application entrypoint. No application code, authentication limiter or expression
implementation is replaced. The existing n8n target definition is reused with
only its application service. [vendor.json](n8n_expression/vendor.json) records
package versions and six installed authentication/controller/expression/execution
source fingerprints per image, required unchanged before and after testing.

Native first-owner setup and password login must succeed. A real Manual
Trigger/Set workflow evaluates a legitimate IIFE to `Native 42 café`. A separate
harmless IIFE uses the underlying Node file API to write exact quote, backslash,
Unicode and CRLF bytes. On 1.120.0, a physical UID-1000 file must match. On
1.120.4, the ordinary IIFE still succeeds while the unsafe expression produces
the captured `ExpressionError` for blocked `mainModule` access and no file.
Terminal execution data is decoded with the image's installed `flatted` library;
an HTTP 200 or a generic execution error alone is insufficient.

The [advisory database](https://github.com/advisories/GHSA-v98v-ff95-f3cp)
identifies 1.120.4 as a branch fix. The
[tagged sandbox source](https://github.com/n8n-io/n8n/blob/n8n%401.120.4/packages/workflow/src/expression-sandboxing.ts)
and actual image deny the tested access. The existing auxiliary n8n lab's 1.121.0
control belongs to a different CVE and is not used as this issue's fixed release.

| Original observation | Confirmed repair | Verified result |
| --- | --- | --- |
| Native 1.120.4 denies execution, but the actual module returns Appears | Make the first branch's 1.120.4 upper bound exclusive | Actual Safe plus repeated AutoCheck refusal |
| A natively refused port yields nil from HttpClient, then `authenticate` dereferences it | Return false with a verbose operation diagnostic before consuming nil | Actual reason-bearing Unknown, without an exception |

The fix retains minimum 0.211.0 and the separate affected 1.121.0 branch. Twelve
focused cases reproduce exactly two failures before the repair and pass **12/0**
afterward, both in the isolated worktree and the campaign checkout. Other version
strings in those cases are unit boundaries, not additional image qualification.
Target metadata and payload defaults are preserved.

## Maintained functional replay

| Profile | Examples / failures / pending | Functional seconds | Qualified scope |
| --- | --- | --- | --- |
| [n8n_expression](n8n_expression/README.md) | 5/0/0 | 65.84 | Native controls, actual Appears, bad password, refused port, two commands on one selection |
| [n8n_expression_fixed](n8n_expression_fixed/README.md) | 3/0/0 | 36.07 | Native positive/denial controls, actual Safe, repeated AutoCheck refusal |

Passive traces record original source paths, requests/responses, check reasons,
command bytes and owned workflow IDs. Both `cmd/unix/generic` commands run with
AutoCheck disabled, independently of prior check state, on the same selected
module. Their exact proof files belong to UID 1000. The payload's apostrophe
restriction is respected: proof data is encoded within an allowed command;
encoded proof data supplies rich bytes within the allowed command.

Two full foreign workflow records and the complete global SQLite workflow-ID
registry must match after every public operation. The module archives/deletes
only its own two distinct workflows. Fixture cleanup removes the preserved
controls afterward, then requires workflow, execution and execution-data tables
to be empty. Fixed AutoCheck attempts issue only login and settings requests,
without entering the exploit body or creating a workflow. Framework sessions
and jobs remain empty; prior OS session totals stay unchanged.

The genuine default five-per-minute login limiter remains enabled. The affected
profile uses native login, actual check, one bad password and two exploit logins.
It avoids duplicate AutoCheck logins in command cases. Native fixture helpers
reuse cookies from real login without forging tokens or disabling rate limits.

## Retained failures, checks and cleanup

The first native pilot fails before module execution because its metadata probe
assumes a flat workflow-package `dist` layout. Resolving the installed CommonJS
entrypoint fixes that harness assumption. Both corrected native pilots pass and
remove their containers immediately.

The first maintained frame has **5/1/0** and **3/1/1**: native controls and both
real commands pass; the actual refused-port exception and fixed-release false
positive fail. The refusal case is deliberately withheld after that incorrect
fixed check. The original output and frozen inputs are retained. The first
repaired frame passes 8/0; self-review then tightens the native denial oracle to
the observed security-error type/message, and the final replay above passes 8/0.

Four new Ruby files pass RuboCop. Full module RuboCop and the standard msftidy
wrapper still report **four pre-existing offenses**: two redundant top-level
platform/architecture declarations and two default-payload declarations. Exact
before/after cop/message/source comparisons are identical: **zero new offenses**.
Direct msftidy metadata checks pass. The focused check repair preserves existing payload defaults; these warnings
remain disclosed. Python parsing,
Compose, excluded acceptance discovery, documentation tidy and diff checks pass.
The **1,186-byte human Scenarios tail** is unchanged, SHA256
`65271a83acd8151d5d2168a55a4a41fb715e71c459fd909f0254354f8b623a4a`.
Automated captures do not provide human Scenarios.

Each stack runs serially with **one capped container**: 1 CPU, 1536 MiB
memory/equal swap, 192 PIDs and a loopback-published port. Explicit project names,
namespace labels, the shared lock and `finally`/runner teardown cover success,
failure and interruption. All **18 new and 494 recorded Docker objects** are
independently absent; the full global running/stopped container inventory and
owned ephemeral networks/volumes are empty. No images/build caches are pruned.

Self-review summary: the stated check, authentication-negative, command and
workflow-cleanup paths are qualified. What looks good: independent native gates,
physical proofs, unchanged vendor files and complete foreign-record preservation.
Concerns: the four pre-existing lint offenses and untested default fetch/Windows,
member-role, MFA, other-release, proxy and external-database paths remain explicit.
Suggested next step: independently calibrate the normal fetch/session path before
assessing its delivery and workflow lifecycle.

## Evidence

Immutable capsules under `/Users/dwelch/.codex/reports/`, sealed by `SHA256SUMS`,
retain frozen inputs, commands, native workflows/executions, physical files,
original module traces, resource counters and exact-ID cleanup receipts.
The original faults are in `n8n-expression-original-faults-20261121T090729`;
the initial repaired replay is `n8n-expression-first-repaired-pass-20261121T091550`.
The final capsule is `n8n-expression-maintained-20261121T092004`. Private
qualification, unit before/after and lint-baseline pointers are in
`tmp/n8n-expression-feasibility/`; temporary local paths are not repository
dependencies.
