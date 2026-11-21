# Calibre sessions and genuine fixed-release controls

Three freshly executed profiles pass **7/0**, using and closing **six real
sessions**. Five published profiles retain **24/0** after current-input and
raw-proof audits. The latest eight-profile set therefore passes **31/0**, with
**thirteen sessions used and closed**. Three new profiles and seven historical
cases bring the campaign to **319 runtime owners, 678 qualified profiles and
4,806 historical functional cases**. The broader inventory goal remains active;
other historical profiles are not requalified here. No PR is created.

## Native readiness and actual default selection

The [explicit Python profile](calibre_python/README.md) and
[normal Linux fetch profile](calibre_fetch/README.md) share the genuine pinned
Calibre 7.14.0 application, book and four installed function fingerprints from
the [command target](calibre/README.md). Both first prove local formatter and
genuine HTTP execution with exact physical UID-1000 bytes, then remove the proof.
A separate TCP callback establishes the actual target UID, persistent PID and
return route. The normal shell-selected interpreter is **Python 3.10.12**;
Calibre's bundled formatter interpreter remains **3.11.5**. Those distinct
consumers are observed rather than inferred from the image's package names.

Each stock payload must work independently through `exploit/multi/handler`
before its real owner executes. The Python profile explicitly selects
`cmd/unix/python/meterpreter/reverse_tcp`, with its default fork setting enabled.
The actual console chooses **`cmd/linux/http/x64/meterpreter/reverse_tcp`** after
selecting Linux TARGET 1, despite the module metadata's Python payload default.
The fetch profile therefore omits PAYLOAD on its first owner invocation and
explicitly selects that observed default on the repeat. Both use the same
selected console object within their profile.

The fetch listener binds to `0.0.0.0` while advertising the address proved by the
native callback. This is ordinary payload configuration, not an alternate
launcher or patched transport. The fetch listener uses port 4493, independently
of reverse-handler port 4492. The native control uses the actual stock encoded
payload; script installation checks its SHA256 before execution. The generated
command, installed payload package version and Python stage fingerprint are
retained. The observed Framework runtime is Ruby **3.3.13** with
`metasploit-payloads` **2.0.257**.

For every session, public Meterpreter APIs write the exact physical
`calibre-session` proof as UID 1000 and return the persistent interpreter/process
PID. Native observations bind that PID to its birth time, owning UID and open
callback socket. The original database row must be open with the actual owning
module and payload. Public remote shutdown then removes the process and socket,
closes that original row and restores the entire two-process baseline. Every
physical proof is removed and its absence checked. Fetch payload artifacts and
the host fetch listener must also be absent before another attempt.

All six sessions meet those requirements: one independent handler session and
two actual owner sessions for each family. The real check runs on each first
owner invocation; the second invocation disables AutoCheck and reuses the same
selection. Actual module source traces, encoded commands, JSON/Python request
semantics and both request bodies are audited. Neither family substitutes a
generic command or handler-only session for real owner execution.

## Genuine Calibre 7.16.0 withholding

The [fixed-release profile](calibre_fixed/README.md) shares the same Dockerfile,
system runtime, normal startup, UID and genuine book. Build arguments select the
official **7.16.0** archive and its vendor-published SHA512. No installed vendor
source, payload runtime or HTTP transport is patched. Before and after the run,
all actual runtime values match the committed
[7.16.0 capture](calibre_fixed/installed-7.16.0.json).

Of the four installed function fingerprints, **only
`calibre.db.cli.cmd_list.implementation` differs** from 7.14.0. Bundled Python
3.11.5, the HTTP dispatcher, both template formatter entry points, UID 1000 and
book identity remain identical. This isolates the fixed remote list behavior
without replacing its producer with a synthetic endpoint.

A native-only pilot proves four ASCII/Unicode/LF/combined-quoting templates.
For each, generation leaves the proof absent; genuine local `SafeFormat`
evaluation creates exact physical bytes. After removal, the **identical
template** reaches the actual HTTP endpoint. It returns HTTP 200 with a real
book ID and **`Template not allowed`**, leaving the physical proof absent.
All four pairs pass, pins remain stable and the pilot stack is removed.

The committed functional profile repeats that gate five times: three readiness
controls and one exact-command control before each owner attempt. All **five
local physical positives and five identical-template HTTP denials** pass. Native
JSON/template generation and local execution prove usable syntax, command bytes,
an available formatter and a matching book independently of remote withholding.
HTTP 200 alone supplies no execution verdict.

The actual module check returns reason-bearing **Safe** for 7.16.0. With
AutoCheck enabled and ForceExploit false, the actual owner is withheld twice on
the same selected object. Across the direct check and both attempts, all three
Safe results have the correct reason. Neither attempt reaches the module's
exploit body, calls `exec_calibre`, sends an RPC POST or creates a physical proof.
The automatic-check wrapper itself is visible in the trace.

## Fresh and retained results

| Profile | Phase | Examples/failures/pending | Used and closed sessions |
| --- | --- | --- | --- |
| `calibre_python` | Fresh | 2/0/0 | 3 |
| `calibre_fetch` | Fresh | 2/0/0 | 3 |
| `calibre_fixed` | Fresh | 3/0/0 | 0 |
| `calibre` | Retained, current inputs audited | 8/0/0 | 0 |
| `laravel_token` | Retained, current inputs audited | 9/0/0 | 0 |
| `laravel_token_fixed` | Retained, current inputs audited | 3/0/0 | 0 |
| `laravel_token_env` | Retained, current inputs audited | 2/0/0 | 0 |
| `laravel_token_perl` | Retained, current inputs audited | 2/0/0 | 7 |

The retained profiles' declared inputs still match their original execution
hashes. Independent audits revisit native prerequisites, physical owner bytes,
check/discovery/denial paths, every real session and original reporting-row
closure. Their 24 cases and seven Perl sessions are retained observations,
not new executions or duplicate additions to the campaign totals.

## Retained harness failures

The first session frame passes independent Python readiness, then fails its
assumption that omitting PAYLOAD after selecting TARGET 1 will choose Python.
The actual console selects HTTP fetch, whose uncalibrated listener attempts to
bind the advertised target-return address and fails. The frame is **2 examples,
1 failure**, with one independent session used and closed. No owner execution
is qualified. Its input snapshot, actual selection, bind failure and cleanup
remain sealed. The final profiles cover both the observed default and explicit
Python selection with their own genuine native gates.

The next two-profile frame has **4 examples, 1 failure**. All six physical
session/reporting/process/socket lifecycles pass, but the new Calibre helper's
method-level Python `ensure` also runs after `return super` delegates a fetch
control. Its Python-local attempt is nil, causing a test-helper exception after
the real fetch calibration completes. Delegation is moved outside that cleanup
scope; Python cleanup stays in its own method. Both affected session profiles
are then replayed, alongside the fixed-release profile. The failed frame is
retained and is not treated as a clean passing profile.

Neither failure is classified as a production module or target defect. Existing
Calibre serialization, shared HTTP and console-source repairs remain byte-
identical to the [preceding publication](VERIFICATION-20261121-calibre.md).

## Inputs, resources and cleanup

Audits reconcile **102 current declared inputs** across the eight stated
profiles. The fresh wrapper freezes **65 inputs**; the runner additionally
registers five Framework/support inputs. All current hashes match, including
the console target-selection source and both payload delivery families. The
retained profiles' other inputs are captured separately in the maintained
capsule. No private source/runtime override qualifies these results.

The fresh three-profile run has **twenty zero memory/PID event captures**. The
five retained profiles add 24, giving **44 qualified zero captures**. Stacks run
serially with at most **two capped containers**. The application uses 1 CPU,
768 MiB memory/equal swap and 128 PIDs; session reporting uses 0.2 CPU, 128 MiB
and 64 PIDs. The fixed profile needs only the application. Published application
and database ports bind only to loopback.

Ensure cleanup removes each finished stack immediately. All **nineteen new
Docker objects** from the native pilot and three functional frames are absent.
Rechecking the prior 355 verifies **374 absent recorded objects**. The final
global inventory includes stopped containers and is empty. No owned ephemeral
network or volume remains, and no agent/tool helper container is started.

All eight new Ruby helpers/specs pass RuboCop. Production module, shared library
and previous focused-unit inputs remain unchanged; those source suites are not
rerun here. Their inherited lint and pending limits remain recorded in the
preceding report. Module-document tidy exits 0. Human Scenarios remain the same
1,860 bytes, SHA256
`22d1711b18e4bc9715f81c1add515d2a61c2832300006274a326cb6c06e4b8f2`.
Automated captures do not replace those manual Scenarios.

## Evidence and limits

Immutable capsules under `/Users/dwelch/.codex/reports/` retain frozen inputs,
native/owner output, exact resource identities and independent audits. The
maintained capsule links both failed frames, the native pilot and the preceding
five-profile publication's original evidence.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `calibre-session-default-selection-failure-20261121T042849` | 86 | `fe253476d9fda2ec8cfde3b24d6bacd01d7987fad6c8328ca4d1b3cfaff7c0ba` |
| `calibre-fetch-delegated-ensure-failure-20261121T043303` | 135 | `3224743894fc9ac034d7ac06a5c411d3633020bc7b3f71ffb31b00bfb46d07a8` |
| `calibre-fixed-native-20261121t042949` | 123 | `092abc3d65218b4938aa297747869894ecc3e56cb39266971a6c1c9d861ac38b` |
| `calibre-sessions-and-fixed-maintained-20261121T043734` | 241 | `183d725a1ca48e9912764448bf0eb74f994bf6ed643a146cac6d5f52cd29c9ab` |

Global Windows TARGET 0, other session families, the 6.9 minimum and 7.15 last-
affected runtime boundaries, other releases and empty-library behavior remain
unqualified. Disabled-AutoCheck execution against the fixed release and better
confirmation of HTTP-200 template errors remain separate follow-ups. Earlier
native PHP Meterpreter, Ignition log-state and Laravel duplicate-callback issues
remain recorded. These passing profiles do not settle them.

## Self-review

**Summary:** Two real session delivery families and a genuine fixed release add
seven qualified cases, with all five retained profiles re-audited.

**What looks good:** Actual default selection, independent native readiness,
same-console repeats, physical UID/PID proofs, original reporting closure and
identical-template fixed denial bind the claims to real consumers. All Docker
resources are removed.

**Concerns:** The listed platforms, releases and retained failures still need
qualification; the full valuable-module inventory is incomplete.

**Suggestions:** Continue the uncovered Lucee owners using their documented
Docker target and independently verified CFML prerequisites, then assess the
heavier TorchServe target and remaining Calibre boundaries.
