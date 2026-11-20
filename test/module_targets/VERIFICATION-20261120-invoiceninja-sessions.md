# Invoice Ninja native-gated session qualification

The maintained replay passes **10/0** across five profiles, using and closing
**15 real sessions**: ten owner sessions and five independent stock-handler
controls. Three new Invoice Ninja profiles add **6/0**, reaching **316 runtime
owners in covered paths, 667 qualified profiles and 4,764 historical functional
cases**. The InvoiceShelf repeats add no duplicate campaign counts. No production
module or payload source changes in this tranche.

## Genuine target and prerequisites

The session image derives from the official Linux amd64 Invoice Ninja 5.10.10
manifest `sha256:1999d70953484cc49a3c9386ac8d8a6e8b2730c0302b9901ac14a074f7038fc9`.
It adds pinned Alpine Bash 5.2.26-r0 through the package manager; the official
image lacks Bash. The derived image retains PHP 8.2.21, Laravel 11.15.0 and all
seventeen pinned application/vendor hashes. Package inventory is captured per
run. Fetch uses the image's existing curl. MariaDB 10.6.19, real migrations/seeder
and `ninja:create-account` initialize a genuine disposable application account.

The command/release profiles and their two confirmed source repairs remain in
the [earlier report](VERIFICATION-20261120-invoiceninja.md). The maintained
[recipes](invoiceninja/README.md) now add Bash, PHP shell, Linux fetch and the
separately unqualified PHP Meterpreter readiness profiles.

## Maintained replay

| Profile | Examples/failures/pending | Used and closed sessions |
| --- | --- | --- |
| `invoiceninja_bash` | 2/0/0 | 3 |
| `invoiceninja_php_shell` | 2/0/0 | 3 |
| `invoiceninja_fetch` | 2/0/0 | 3 |
| `invoiceshelf_bash` | 2/0/0 | 3 |
| `invoiceshelf_php_shell` | 2/0/0 | 3 |

Every profile first proves callback reachability and the real application UID,
then launches a stock payload with an independent `exploit/multi/handler`.
Actual file bytes and ownership, public session APIs, fresh PID/birth/socket
observations, healthy HTTP, original database-row closure and restoration of the
full process/socket baseline gate owner execution. Each owner runs twice on the
same selected console object, first with AutoCheck and then with AutoCheck
disabled. No example is pending and no error occurs outside examples.

The first fetch owner selects target 1 and omits PAYLOAD. The observed selection
and real ready session identify
`cmd/linux/http/x64/meterpreter/reverse_tcp`; the independent handler uses the
same stock adapter. The downloaded file disappears and the host HTTP listener
closes after each attempt. Bash and PHP shell select their matching payloads
explicitly. This qualifies target 1's fetch selection, not the PHP default path.

The InvoiceShelf regression checks the extracted common lifecycle helper on its
genuine Laravel 10 runtime and UID 33 as well as Ninja's Laravel 11 and UID 1500.
Source inventories and database state match before and after the run; Ninja
login and InvoiceShelf version responses remain healthy. No private PHP runtime
patch or transport proxy is installed.

All **74 wrapper input files remain unchanged**, and every
runner-declared source digest still matches. All **44 memory/PID event
captures are zero** and **24 exact Docker objects are
independently absent after cleanup**. Stacks run serially with at most
**3 capped containers**: the app (1 CPU, 1024 MiB,
128 PIDs), MariaDB (0.5 CPU, 512 MiB, 128 PIDs) and ephemeral Framework reporting
PostgreSQL (0.2 CPU, 128 MiB, 64 PIDs), with equal swap caps. The InvoiceShelf
regressions need only two services. The runner removes finished containers,
networks and ephemeral volumes in ensure, including after failure.
The final global running/stopped container inventory is empty; an independent
recheck verifies all 188 recorded Docker objects from
the Ninja investigation and its retained phases remain absent.

## Retained failures and limits

| Attempt | Actual examples/failures/pending | Finding and owner verdict |
| --- | --- | --- |
| Official-image Bash native control | 2/1/1 | Bash missing; callback and UID pass, owner withheld. The derived image supplies this prerequisite. |
| PHP staged Meterpreter native control | 2/1/1 | No usable ready session before timeout; owner withheld. |
| PHP inline Meterpreter native control | 1/1/0 | No usable ready session; an established target socket remains after local job/session cleanup. The safety cleanup gate stops before the dependent owner case. |

The six-profile baseline that captured the PHP failures also passes Ninja and
InvoiceShelf Bash/PHP shell paths (**8/0** across four profiles). Its 69 frozen
inputs remain unchanged, 56 resource captures are zero and all 30 exact Docker
objects are removed. Native callback/interpreter/application controls pass, but
that does not explain the PHP Meterpreter readiness failures. Their cause stays
unresolved and they add no qualification. They were not rerun merely to repeat
the failure after the fetch-only helper extension. The retained missing-Bash
pilot removes all nine recorded Docker objects. No failed stack is kept running.

The PHP default, Windows, other releases, nginx/FPM, TLS and other payload
families remain unqualified. The historical human Scenarios sections are
unchanged; the module documentation links these automated results separately.
All seven changed/new Ruby helper/spec files pass RuboCop without offenses;
the module documentation passes msftidy_docs and the diff passes whitespace checks.

## Retained evidence

Verified local capsules preserve complete logs, native and owner observations,
input snapshots, audits and exact resource cleanup receipts.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `invoiceninja-sessions-maintained-20261120T224358` | 242 | `f6e000d7e56778e509e9ff5b833f6ef8788f6c14645fa3362463761993d6ac22` |
| `invoiceninja-fetch-pilot-20261120T224120` | 96 | `6e7146eedce60515f2ec9142c77aef1f4ebe5b349bf8b1199552b4b5376780e3` |
| `invoiceninja-session-baseline-20261120T222606` | 257 | `ae10fc649316b27d1b3cf2f1b0f39b27611161a662f29843c53d60f8bf6fa9a3` |
| `invoiceninja-session-missing-bash-20261120T221814` | 128 | `3c5787f86b266484fdf082c7a7ed2244e98f540fe9b287218599441db8c15d11` |

## Self-review

**Summary:** Three new native-gated session profiles pass with genuine owner
execution, repeat use and cleanup. No PR is created; the broader goal stays active.

**What looks good:** Independent stock handlers, physical file/UID proofs,
original reporting-row closure and process/socket restoration distinguish a
working session from a banner. Shared helpers retain both application protocols.

**Concerns:** The two native PHP Meterpreter failures remain unresolved and the
normal PHP default is unqualified. The image's missing Bash was a prerequisite
failure. The previous production-module lint exceptions are unchanged.

**Suggestions:** Investigate the retained PHP readiness captures separately,
without weakening the gate or substituting a private payload runtime. Extend
qualification only after an independent native session passes the same lifecycle.
