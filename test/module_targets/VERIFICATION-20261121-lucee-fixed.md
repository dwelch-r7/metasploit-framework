# Lucee genuine fixed-release controls

The new [fixed-release profile](lucee_fixed/README.md) qualifies **3/0/0**.
Both existing Lucee command profiles are freshly replayed after a native fixture
correction, giving one clean **11 examples, zero failures, zero pending** frame.
Eight unrelated profiles retain 31 qualified cases with unchanged declared
inputs and retained raw proofs. The latest eleven-profile set therefore has
**42 qualified cases** and **thirteen retained sessions used and closed**;
there are no new session runs here.

One new profile and three historical cases bring the campaign to **321 runtime
owners, 681 qualified profiles and 4,817 historical functional cases**. Replayed
cases do not add to those historical totals. The broader inventory remains
incomplete, and no PR is created.

## Genuine fixed target and independent positive controls

The recipe pins official Linux amd64 **Lucee 5.3.7.47** at image digest
`sha256:233f371c2b77d3b69ae35edcf51123ab074480f76408d83399a5d9bd6d171de4`.
The [vendor advisory](https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r)
lists this release among the CVE-2021-21307 fixes. Native runtime observations
establish Java **11.0.9**, UID **0**, webroot `/var/www/`, context
`/opt/lucee/web/context/` and no scheduled jobs. The unchanged vendor JAR has
the same SHA256 before and after each accepted run:
`da47c8fbd13cbfe12544d18009e4cf00d09499b34c362a6b2b0e8c95ff8dc114`.

Native Bash and genuine CFML execute exact ASCII and combined quoted, Unicode,
multiline and metacharacter commands. Exact-command controls run again before
both owner attempts, producing **eight physical command proofs** in the fixed
profile. A separate control verifies nonempty stdout and stderr and its physical
file, so optional-output handling cannot silently replace real diagnostic bytes.

Before readiness is accepted and again before each owner attempt, normal CFML
writes a template into the real Lucee context directory. The test reads its
exact physical source as UID 0, requests it through the normal `/lucee/`
mapping, verifies the interpreted marker, and removes it. These **three
context-write/interpretation pairs** establish that CFML, directory permissions
and the mapping work independently of the vulnerable endpoint.

After each positive is removed, the original missing-field check, base-path and
traversal-write requests all return empty **404** responses. All **nine native
requests** leave the physical target absent and do not create the image-write
temporary directory. These response expectations follow a separately captured
native pilot. Vendor code and HTTP handling are unchanged; the standalone
mounted native application supplies only the independent controls.

## Actual module behavior

The real `exploit/linux/http/lucee_admin_imgprocess_file_write` check returns
**Safe** with reason **The target is not vulnerable**. Two actual run attempts
then repeat on the same selected console object with AutoCheck enabled and
ForceExploit disabled. Each returns the same real Safe result. Method and HTTP
events establish that each check reaches the actual vendor endpoint and gets
its empty 404 response, while the production exploit body, CFML stub producer
and command execution method are never entered. The independently proven
command's physical output file stays absent.

The attempts explicitly select Unix TARGET 0, `cmd/unix/generic` and the normal
`AllowNoCleanup=true` sessionless option. They do not qualify default payload
selection, sessions or automatic FileDropper cleanup. Native positive templates
and command proof files are removed by the fixture and verified absent.

## Fixture failure and correction

The first native-only pilot succeeds. The first maintained fixed-release frame
then fails during native readiness: `cfexecute` leaves its empty error-output
variable undefined, and the fixture dereferences it. That frame remains
**3 examples, one failure, two pending**. No owner runs and no module verdict
is assigned to that failure. Its original inputs, response, traces and cleanup
are sealed before the correction.

The standalone fixture now treats an absent optional output variable as empty.
Exact nonempty output, nonempty stderr and physical file checks remain required.
No production module or library changes. A fresh native pilot passes with
nonempty stdout, and the maintained fixed profile passes its separate stream
control, exact command controls, positive context writes and actual owner checks.

Because the native fixture is shared, both vulnerable profiles are replayed
with the corrected file. Each passes **4/0/0**. Their eight actual commands,
twenty native physical command proofs, eight exact module-generated CFML sources,
same-selection repeats, real scheduler task deletion/listener closure and final
wrong-password rejection requalify. All profiles in the new frame finish
successfully. The earlier mixed failed frame remains historical evidence in
the [original Lucee report](VERIFICATION-20261121-lucee.md).

| Fresh profile | Examples/failures/pending | Actual owner outcome |
| --- | --- | --- |
| `lucee` | 4/0/0 | Four exact commands and two same-selection pairs |
| `lucee_scheduled` | 4/0/0 | Four exact commands, task deletion and authentication negative |
| `lucee_fixed` | 3/0/0 | One direct Safe check and two repeated AutoCheck refusals |

## Inputs, checks and resource cleanup

All **127 current declared inputs** reconcile. The fresh frame has twelve zero
memory/PID event captures; the eight retained Calibre/Laravel profiles add 44,
giving **56 qualified zero captures**. Their 31 cases and thirteen sessions are
retained current-input proofs, not new executions in this tranche.

Fresh phases run serially with at most **one application container**: 1 CPU,
768 MiB memory/equal swap, 128 PIDs and a loopback-only published port. The
retained latest set has a historical maximum of two capped containers. No agent
or tool helper container starts here.

Both native pilots, the failed frame and all three final profile stacks are
removed immediately. Their **six containers and six ephemeral networks** are
independently absent. Rechecking the prior 393 objects establishes **405 absent
recorded objects**. Both Docker contexts reference the same daemon and show
**zero containers, including stopped containers**; no owned ephemeral network or
volume remains. The user's broader cleanup request is checked against the full
inventory, without a namespace filter; no unrelated container needs removal.

Both new Ruby files pass RuboCop. The changed module document passes tidy with
no messages, and its original **8,277-byte Scenarios tail** remains unchanged:
`203b92b8ee6f7d6104aaa5e2d40c7c48ebc92eb009a2992ae0bd9d4b7cc72bcb`.
Automated results do not replace human Scenarios.

## Evidence and remaining scope

Immutable capsules under `/Users/dwelch/.codex/reports/` retain frozen sources,
native vendor identity, raw responses, physical proofs, actual method/request
events, audits and exact cleanup identities. Publication binds the final
documentation and committed blobs separately.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `lucee-fixed-native-ready-20261121t055305` | 130 | `949a32ac8a945957c65e7fc16858152b34e1a98291b5439e91f71b2d994e2f8f` |
| `lucee-fixed-optional-output-fixture-20261121T055516` | 65 | `c127585119e3e03020efbac97d8a3f06fea25546cb365ab836b3df8c54781df7` |
| `lucee-fixed-native-rechecked-20261121t055747` | 130 | `26bc31dedadc2ed8bfaf11009f0003ec6d99fb33ecdf642312c4e7c17b06eff0` |
| `lucee-fixed-maintained-20261121T055846` | 283 | `c1e850226f21be8ddca4ce0547e5c9e8f21fac77b38385f186d53ec3a4de8ddb` |

Default session payloads and their lifecycle/reporting, automatic FileDropper
cleanup, Linux dropper architectures, Windows, IPv6 and other release branches
remain unqualified. Earlier Calibre, PHP Meterpreter, Ignition log-state and
Laravel duplicate-callback investigations remain open.

## Self-review

**Summary:** A genuine fixed-release profile distinguishes a blocked endpoint
from broken native execution, context permissions or HTTP mapping.

**What looks good:** Actual module checks, physical positives and negatives,
same-selection repeat attempts, frozen inputs and exact cleanup are verified.
Both consumers of the corrected native fixture pass fresh replays.

**Concerns:** The listed delivery/session variants and broader module inventory
remain incomplete. The failed native-readiness frame stays failed.

**Suggestions:** Calibrate actual default session selection and automatic
cleanup next, then cover Linux droppers and another valuable uncovered owner.
