# Craft CMS image-transform investigation — 2026-11-19

Qualification remains in progress for
`exploit/linux/http/craftcms_preauth_rce_cve_2025_32432`. Campaign totals remain
**309 runtime owners, 638 qualified profiles and 4,609 historical functional cases**.
The stock PHP Meterpreter prerequisite is inconsistent; no new counts are added.

## Verified source repairs

- Platform metadata used one string, normalizing to Linux alone. The original
  console rejected Unix command payloads before invoking check/exploit. An array
  restores both platforms: 9 focused cases/2 failures before, zero after.
- Empty PHP session configuration was rendered as `no value`; the original owner
  tried `/no value/sess_<SID>`, or `/var/lib/php/sessions` with AutoCheck disabled,
  although native inclusion proved `/tmp`. Shared discovery now verifies a fresh
  session marker before using a directory; `SESSION_PATH` supplies an explicit
  override. The combined path/platform regression moved from 28/17 to 28/0.
- A subsequent real space-containing path exposed a test-fixture gap: phpinfo
  emits `&nbsp;` for ordinary spaces. The owner used nonbreaking spaces in the
  filename. The captured-format regression moved from 35/7 to 35/0. The repair
  decodes display entities on a response copy, preserving raw response bytes,
  literal nonbreaking spaces and operator-supplied option values.

The module docs also reversed affected and fixed ranges. They now follow the
[vendor advisory](https://github.com/craftcms/cms/security/advisories/GHSA-f3gw-9ww9-jmc3).
Historical human-written Scenarios remain byte-for-byte unchanged.

## Retained native and owner evidence

A genuine filesystem/volume, authenticated PNG upload, exact image reads and
named transforms establish ordinary application behavior. Anonymous sessions,
CSRF, actual session-file bytes and independent inclusion establish the primitive.
The fixed release rejects object handles while continuing named transforms.

The initial 20-case owner replay recorded 14 passes and 6 failures. Both command
targets produced exact quote/percent/backslash/dollar bytes in six default-path
executions. Six Bash and inline-x86/staged-x64 fetch sessions were used, reported
and closed. A natively refused port returned reason-bearing Unknown. The fixed
profile passed 4/0. The explicit-space profile failed 4/4 due to the captured
phpinfo presentation defect. All 102 ordinary native checks passed before/after;
29 stable snapshots matched and 186 resource-event captures were zero.

One independent native PHP Meterpreter session passed, was used as UID 82 and
closed with a separate SQL record. A subsequent native run failed readiness with
repeated pending connections. Its dependent PHP Meterpreter owner case was
withheld; PHP command execution had already passed. This retains a payload/runtime
investigation without assigning that native failure to the Craft exploit. The
[earlier investigation](craftcms/README.md#php-meterpreter-investigation) and
explicit experimental source override remain separate from stock qualification.

## Maintained replay

The [maintained profiles](craftcms_assets/README.md) and
[functional spec](../../spec/modules/exploits/linux/http/craftcms_assets_target_spec.rb)
cover 12 affected, 7 explicit-path and 4 fixed cases. The maintained stock replay
records 21 passes and 2 failures, with no pending or outside-example errors:

| Profile | Examples/failures | Actual owner sessions used/closed |
| --- | --- | --- |
| Explicit session path | 7/0 | 0 |
| Fixed release | 4/0 | 0 |
| Affected release, stock runtime | 12/2 | 6 |

All 14 positive command proofs pass; the missing override and all six fixed-release
attempts withhold their command proofs. The two failures are the independent PHP
Meterpreter prerequisite and its withheld dependent owner case. The root checkout
also passes 42 focused examples (35 source cases plus 7 automatically loaded support
cases), source/fixture Ruby syntax and RuboCop, module tidy, and module-doc checks.
All 144 frozen inputs remain unchanged; 102 ordinary native checks, 34 stable
snapshots, 216 zero resource-event captures and 18 independently absent owned Docker
objects pass. The independent SQL snapshot confirms all six owner sessions closed,
and unrelated initial container IDs remain present.

The explicit experimental receive-source comparison passes 12/0. Its independent
native PHP session and all eight owner sessions are used and closed, including
first/repeated staged PHP Meterpreter sessions. Independent SQL confirms closure;
34 ordinary native checks, 17 stable snapshots, 114 zero resource captures and
all six owned Docker object removals pass. Unrelated initial containers remain.

The actual loaded source is
`0817e293eaaa5f6837a125cfc8649b354c7e77f4b9e12ae0d83dd0d24d4e3244`,
written only under the run's supported Framework configuration override. All 142
declared repository inputs remain unchanged. The orchestrator separately freezes
the explicitly requested PHP source with the hash above. The experiment changes
no installed gem or project dependency. It
supports the earlier receive-path investigation, while the specific failing runtime
instruction in the retained stock run remains untraced. This comparison cannot
qualify the stock runtime.

## Evidence capsules

Capsules are retained under the task's private `~/.codex/reports` directory.
Each manifest hashes its frozen inputs and raw results.

| Capsule | SHA256SUMS SHA256 |
| --- | --- |
| `craftasset-functional-20261119T114121` native affected/fixed | `18bb58991de3adea886c6fb69aeeb903e78ac72f17f8d9a37cfb04cc5fa212ed` |
| `craftasset-functional-20261119T114517` original command-platform failure | `b45e23fae3d68f1ae165971a9c71bd285d9403f8d82892bb0edaeba84219a554` |
| `craftasset-functional-20261119T115234` original PHP path failures | `5d5d676d6910348a60379a5535597c4932e1c486376e86d0caf615be6692231a` |
| `craftasset-platform-confirmed-fix-20261119T120150` platform regressions | `d82d03b640cd030ce021459e5472f085a832bb061147c992a1dbba932bb2587d` |
| `craftasset-functional-20261119T120116` native explicit path | `6057c926c7fa95a921986b334d9d79fe25f3ff75cb99b66f26ba95bab318199f` |
| `craftasset-functional-20261119T121032` native PHP pass | `eec377e3fcc1e71636195e70e0a53eca75f61e47d102637e109511fd9f7864ce` |
| `craftasset-independent-sql-20261119T121037-9680f0` native SQL supplement | `e7ced4d6a98dabad8d2316e5e8c17e464f9ff5a2a46e2bfb01a5e752810b41c3` |
| `craftasset-functional-20261119T122348` mixed stock pilot | `b64a1e2aaa3a144aa2efe86f05e2d38ee07f9123ef177527973de3aaf462dc94` |
| `craftasset-functional-20261119T125208` maintained stock replay | `bd217b1fa5fa1d279abe7f928bf2123ca82ff98130c7dc4cde15960d97c7b2f3` |
| `craftasset-functional-20261119T130542` explicit experimental comparison | `61a89c328bb8c3bb27930601c291ba862f166be47be4048229f41983e891434a` |
| `craftasset-session-path-confirmed-fix-20261119T122525` path regressions | `46c1b99f744342eb75dd2644b8328215d9f0428b2305ef5338edf75aa33d845f` |
| `craftasset-phpinfo-whitespace-confirmed-fix-20261119T125140` entity regressions | `48369778ea044514f8539f4e20ff54164753821a0ff314dc45cd93d20cabff6e` |

The mixed pilot retained 146 unchanged declared inputs and independently confirmed
all 18 owned Docker objects absent. Three initially unrelated container IDs were
absent by the final inventory; the cause is unverified. The original PHP-path
pilot separately retains the same limitation for two missing initial IDs.
Cleanup commands were
limited to the exact task-labelled Compose projects. The copied SQL collector
initially wrote to its prior directory; its unchanged raw output is included in
the mixed capsule, and the earlier native SQL output is sealed separately. The
collector output path has been corrected for future runs.

## Review

**Summary:** Reproducible target fixtures and three grounded source repairs;
stock PHP Meterpreter qualification remains unfinished.

**What looks good:** Native application/session gates, exact command bytes,
actual used/closed sessions, independent SQL and scoped cleanup provide evidence
beyond an HTTP status or a successful console command.

**Concerns:** Stock PHP Meterpreter remains unqualified. PHP native readiness
varies, and the current failure was not newly traced to a specific runtime instruction. Craft 3.x/
5.x, custom cookie names, non-file session backends and unlisted deployments are
outside this fixture pair.

**Suggestions:** Investigate the shared PHP receive path before stock
qualification; retain both native outcomes and the explicit comparison. No PR
is requested.
