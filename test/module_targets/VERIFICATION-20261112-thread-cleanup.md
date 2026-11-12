# Module spec thread cleanup — 12 November 2026

Three unit-spec lifecycle fixes remove the monitor leak observed in the
[published Ruby 3.3 CI job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43137573182/job/130916482743)
for `043a4c9`. That job runs 18,251 examples without an example failure, then
fails the unchanged six-thread suite audit because seven threads remain.
This report records a focused reproduction and fix, not a successful full CI run.

## Cause and verification

The ownCloud and 4gaBoards unit contexts call the lazy `framework.threads`
accessor during teardown. That creates a monitor when no manager was needed;
killing only managed workers leaves the separate monitor alive. Two Jenkins
duplex examples also allocate real managers whose monitors survive their tests.
Creation stacks and manager/monitor object identities identify all four owners.
The suite-end provider is nil in both original and fixed captures; provider
contamination is not needed to explain this particular CI failure.

The fix checks `threads?` before accessing a manager, stops and joins owned
workers and monitors, and restores the original ThreadFactory provider even
when context setup fails. Jenkins teardown joins only live workers because its
examples already observe terminated worker exceptions through `Thread#value`.
Production modules, libraries, the shared cleaner, thread logger, auditor and
six-thread threshold remain unchanged.

The identical five selected examples, order, seed 39416 and observation helper
give these results:

| Revision | Examples | Example failures | Outside errors | Suite-end threads | Owned monitors | Actual exit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original | 5 | 0 | 1 | 7 | 4 | 1 |
| Fixed | 5 | 0 | 0 | 3 | 0 | 0 |

All **107 examples** across the four implicated files also pass, with no pending
examples or outside errors. The parent independently repeats those 107 examples
on imported source `ef30f25521d5ebaa8c3b57e47e38a93a3b0136d4`: exit zero, three
baseline threads, no surviving owned monitors, original provider restored.
Both runs use Ruby 3.3.13 and seed 39416. No full local suite is run.

A separate injected loader failure demonstrates setup cleanup: both versions
correctly fail the injected example, but only the fixed version removes its
monitor and restores its prior provider. This deliberately failing probe is
kept separate from passing regression results.

The parent's first independent attempt stops in `spec_helper` with zero examples
because its isolated configuration omits the existing local test database
configuration. Selecting that existing configuration explicitly resolves the
setup prerequisite; no service or configuration is created or changed.
The original blocked capture remains in the evidence package.

AST comparison verifies identical example bodies and identical non-hook code
in all three changed files. RuboCop, Ruby syntax and whitespace checks pass.

## Functional qualification review

The unit files are recorded as support inputs by five ownCloud and four
4gaBoards manifests. Their strict input hashes change even though the acceptance
entrypoints never load them. The Jenkins unit file appears in no selected
functional input record. The parent scans actual chosen result records, not
only manifest support lists, to establish this impact.

For all nine profiles, the parent verifies the unchanged manifest, acceptance
entrypoint, original RSpec example file paths and every other recorded input.
It also checks 19 additional consumption inputs, including the runner and both
spec helpers. Nine isolated acceptance **dry runs** record actual loaded
features and confirm that none of the three changed unit files is loaded.
Dry runs load declarations only; they execute no target behavior and add no
functional examples.

The explicit review preserves **97 previously verified functional examples**:

- `owncloud_graph_0_3_0`, `owncloud_graph_0_3_0_prefix`,
  `owncloud_graph_0_3_1`, `owncloud_graph_hostname_db`, `owncloud_unrelated`.
- `4gaboards_3_3_8`, `4gaboards_3_3_9`,
  `4gaboards_registration_disabled`, `4gaboards_unrelated`.

Original result files and their input digests remain unchanged. The review is
limited to the exact old/new unit hashes and those nine original results; it
does not relax the shared runner's strict changed-input checks. The private
checkpoint audit records this exception explicitly. Every remaining selected
functional input stays byte-identical, including all 55 Pi-hole inputs.

The checkpoint therefore remains **208 qualified modules, 184 profiles and
1,968 functional examples**, with no new functional executions claimed here.
The three previously excluded profiles remain excluded. No Docker containers
are started for this follow-up; the global container inventory remains empty.

**Summary:** Owned unit-fixture monitors are cleaned up, with an unchanged audit
and a matched reproduction of the CI symptom.

**What looks good:** The original and fixed ownership captures agree with source
and AST review. Independent parent verification confirms the focused suite and
the bounded acceptance non-consumption decision.

**Concerns:** Linux and other Ruby versions still require remote CI results.
The nine functional profiles were reviewed for unchanged execution inputs,
not replayed after this unit-only edit. Any further source or consumption-input
change invalidates the corresponding exact-hash review.

**Suggestions:** Inspect the new published head's CI results and continue the
remaining container-feasible module campaign serially.

## Evidence

The worker's original/fixed package contains 83 read-only, independently copied
entries; manifest SHA256:
`e6e29dc6a82dced2beaa987633ade1a24c3e1f8a40b5b5b608632f6683d2c398`.
The parent's combined package `module-spec-thread-cleanup-20261112` contains
**258 entries and 99 source inputs**, including raw thread inventories, process
receipts, AST comparisons, loaded-feature records and unchanged original
functional results. Its manifest SHA256 is
`2661b2781ae867522d80c8c6c461808ec7a4531cb2d3e963b35e765c004be7ae`.
Every entry is rehashed, read-only and single-link. The separate worker branch
preserves `f9053a07679cfe25eff132c85aba4d72bf54f041`. Publication is to the user's
fork branch without a PR.
