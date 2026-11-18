# Acceptance checkout provenance repair, 2026-11-18

The SMB and Meterpreter reusable acceptance workflows could test upstream's default Framework branch when triggered by this fork. Both Framework wrappers now supply the event repository and SHA, and the shared workflows use that selection for test and report checkouts. Existing external callers retain the upstream repository default and their existing Framework ref behavior.

This is a CI source-selection repair. It adds **zero** module owners, qualified profiles or functional cases; the latest owning checkpoint remains **288 runtime owners in covered paths, 582 qualified profiles and 4,053 historical functional cases**. The broader campaign remains active. No PR is created.

## Actual original execution

| Workflow result | Workflow revision | Actual Framework checkout | Observed outcome |
| --- | --- | --- | --- |
| [PostgreSQL checkpoint Meterpreter job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44202447641/job/134459730121) | `afa0c27cbeb6dcd0af580115f14b3dd33c21e9fd` | `rapid7/metasploit-framework` master `4f30a91e239b3cd3de5a7810b5dc28cd5586c1e4` | Linux Mettle: 51 examples, one failure |
| [Fetchmail checkpoint SMB job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44207957203/job/134478680589) | `308e0344a91ad1c1a08989e3eb986eac9dfdc139` | The same upstream master commit | 20 examples, zero failures |

Full job logs show the selected repository, checkout of upstream master and subsequent `git log -1 --format=%H`. A workflow's associated head and green status do not establish execution of that head. These jobs also do not run the opt-in module-target profiles. The local owning results retain independent source-path/hash, native/session, actual reporting and cleanup evidence.

The Mettle failure is a `ChildProcessTimeoutError` in `post/test/search` over `linux/x64/meterpreter_reverse_http` with `base64_transforms.profile`. Output reaches setup's directory-creation step, then timeout recovery interrupts the post module. The example takes 619.32 seconds. The underlying mkdir/cd/pwd/transport stall is **unverified**; the trace does not establish a pgpass defect. Both original attempts are preserved without retry or cancellation.

## Source selection and compatibility

Both Framework wrappers pass `github.repository` and `github.sha`. The new optional `metasploit_framework_repository` input defaults to `rapid7/metasploit-framework`; the existing Framework commit input remains unchanged. All four test/report checkout sites consume the chosen repository and commit.

| Caller | Resulting selection |
| --- | --- |
| Framework fork push | Triggering fork and exact event SHA |
| Framework pull request | Base repository and the existing PR merge event SHA |
| Meterpreter manual dispatch | Dispatch repository and selected branch/tag event SHA |
| External caller with default/blank Framework ref | Existing upstream default/event-ref selection |
| External caller with explicit branch/tag/SHA | Existing upstream repository and supplied ref |
| New repository override with explicit SHA | Supplied repository and SHA in both test and report |

SMB still has no manual-dispatch trigger. GitHub documents the [pull-request merge SHA](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request) and [reusable caller context](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations#github-context). The inspected [checkout action's input selection](https://github.com/actions/checkout/blob/11d5960a326750d5838078e36cf38b85af677262/src/input-helper.ts) uses the event ref implicitly only for the caller repository; its [source provider](https://github.com/actions/checkout/blob/11d5960a326750d5838078e36cf38b85af677262/src/git-source-provider.ts) otherwise resolves an omitted ref to the selected repository's default branch.

Pinned existing [Payloads](https://github.com/rapid7/metasploit-payloads/blob/122bc37d53e9b1a261580897ac59d219c6e3b635/.github/workflows/metasploit-framework-meterpreter_acceptance.yml), [Mettle](https://github.com/rapid7/mettle/blob/4dd76aed028fff0a214564cb4c389947b71a194b/.github/workflows/metasploit-framework_acceptance.yml) and [RubySMB](https://github.com/rapid7/ruby_smb/blob/b303067d412eb18994260573030b0ba3c69e263e/.github/workflows/metasploit-framework_acceptance.yml) callers omit the new input. Their Framework ref expressions and candidate build flags are preserved. Existing triggers, permissions, payload selectors, build steps and artifact code are unchanged.

## Verification and limits

Static verification passes **29 YAML/scope checks and 36 modeled checkout-selection cases**, including test/report agreement and the pinned external callers. This models documented action behavior; it does not execute GitHub's checkout action. The imported source blobs match the checked bytes, and whitespace validation passes.

Meterpreter workflow/expression actionlint passes with shellcheck disabled. Full four-file actionlint returns exit 1 before and after with the **same twelve diagnostics**: eleven shell diagnostics and the SMB report's existing undefined `matrix.ruby`. Four-file expression-only lint likewise retains that single existing report diagnostic. No new diagnostic is introduced; full lint is not claimed green. No dependencies are installed and no Docker, RSpec or build runs for this source-selection repair.

Subsequent SMB test/report execution now proves the intended repository and exact checkout HEAD, as recorded below. Selected completed Meterpreter jobs also prove their source below; the remaining matrix and final report are still observed independently. The original search setup stall remains a separate investigation.


## Subsequent execution evidence

The [new SMB execution](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44216722588) passes **20/0**. Full [test job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44216722588/job/134508305304) and [report job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44216722588/job/134515705704) logs both show `dwelch-r7/metasploit-framework` and actual HEAD `0fc4834ef4cb1705b60ff6d7eef6ee3cb308243f`. This proves the repaired source selection for SMB test/report execution. It does not prove Meterpreter execution or run the opt-in module-target profiles.

A separately preserved [Fetchmail checkpoint Meterpreter job](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44207956779/job/134478680905) executes upstream `4f30a91e239b3cd3de5a7810b5dc28cd5586c1e4`, with **46 examples/one failure** on macOS Intel. The HTTPS payload with `minimal_uris_headers.profile` fails `post/test/cmd_exec`'s single-quoted echo assertion; adjacent double-quoted echo and stderr checks pass. The actual mismatched bytes are not printed and the root cause remains unverified. This is not evidence of a Fetchmail owner regression. No workflow is retried or canceled. The remaining Meterpreter matrix and final report remain separately observed.

Completed [Ubuntu/PHP 5.3](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44216722583/job/134508307295) and [Windows/Python 3.8](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44216722583/job/134508307352) Meterpreter jobs independently log `dwelch-r7/metasploit-framework@0fc4834ef4cb1705b60ff6d7eef6ee3cb308243f` and pass **91/0** and **100/0**, respectively. The overall workflow still reports queued while other matrix jobs run. `gh run view --log` withholds logs until the whole run completes; the completed-job REST log endpoint supplies the original full logs. This proves source execution for those two jobs only. The remaining matrix, macOS/Mettle and final report are not inferred from them. No opt-in module-target cases are added to qualification totals.
