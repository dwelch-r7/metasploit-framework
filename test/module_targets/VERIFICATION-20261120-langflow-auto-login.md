# Native Langflow auto-login commands and sessions

The maintained Langflow 1.8.4 profiles pass **14/0**, with zero pending or
outside-example errors, after two confirmed repairs: shared `python/exec`
command generation and the module's payload process boundary. Ten owner sessions
and five independent handler sessions are used and closed. The authenticated
counterpart regression passes **10/0**, including six additional used/closed
sessions. Every session restores its process/TCP baseline and closes its original
persisted reporting row.

| Profile | Result | Coverage |
| --- | ---: | --- |
| `langflow_auto_login_enabled` | 2/0 | Version, exact bytes, Unicode/quotes/CRLF, repeated selection and disabled AutoCheck |
| `langflow_auto_login_disabled` | 2/0 | Genuine authentication contrast and anonymous token denial |
| `langflow_auto_login_default` | 2/0 | Native staged handler, actual automatic default and repeated owner session |
| `langflow_auto_login_sessions` | 8/0 | Native-gated staged/forking, staged/nonforking, inline Meterpreter and Python shell paths; each owner repeats |
| `langflow_execution` | 10/0 | Existing authenticated owner's commands and six sessions |

The four new profiles add **one runtime owner, four qualified profiles and 14
historical functional cases**, including five independent handler cases. Campaign
totals become **314 runtime owners in covered paths, 655 qualified profiles and
4,725 historical functional cases**. The authenticated regression is not added
again. Reproduce using [the target README](langflow_auto_login/README.md).

## Final evidence audit

The final replay is `20261120T173837-80ad16`. All **83 recorded input hashes**
still match the tested files. The new native before/after controls pass 182
assertions, and all twelve real token-loot files match tokens received from the
actual backend. Passive tracing verifies fork settings on execution copies,
including false on both nonforking owner runs. Their live callback processes have
backend parent PID 42; forking staged/inline callbacks have parent PID 1. All are
absent after shutdown; no zombie exception or backend signal is used.

Inspected resource caps match the recipes: application 1 CPU/3072 MiB/256 PIDs,
reporting database 0.2 CPU/128 MiB/64 PIDs, and the legacy console
1 CPU/768 MiB/256 PIDs, each with equal memory/swap limits. All resource-event
checks pass. The host source suites pass **51/0** and **11/0**, each including
seven support cases; this represents 48 focused helper/payload/owner cases.
Changed Ruby lint, all three module tidy checks, module-doc tidy and Python
syntax checks pass. The full local RSpec suite was not run.

The final evidence capsule is `langflow-auto-login-maintained-20261120T173835`:
**442 verified files**, manifest SHA-256
`7ad10030950b062a91432a6667c09265933e3735bd1150461af63ee8a4b9689d`.
The source/fixture failures below are separate evidence and add no qualified
counts.

## Native application controls

The stock Linux amd64 image is the existing Langflow digest
`sha256:836a3996d52cfc6be24e1e01a56171c1a00f603e05cebc65b6d10acf3fbf016d`.
Its OS is Debian GNU/Linux 13, Python is 3.12.12 and application UID is 1000. The installed
login and validation source hashes match upstream revision
[`6cb87cca4c868cad096fc14139e73157740b7419`](https://github.com/langflow-ai/langflow/tree/6cb87cca4c868cad096fc14139e73157740b7419).

Two configurations retain `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=false` and contrast
`LANGFLOW_AUTO_LOGIN=true` with `false`. Independent requests verify the real
version/source, wrong-password rejection, valid authentication, protected
anonymous validation, exact native file bytes/UID, repeated anonymous token and
validation chaining when enabled, and unchanged flow IDs. Correct authenticated
execution still works when auto-login is disabled. Version alone does not prove
that the anonymous chain is available; the module returns version-based Appears
for both configurations.

Every owner command first executes as the identical bytes through an independent
native validator control. The owner must then reproduce those bytes or correctly
withhold execution when it cannot retrieve a token. The repeat shares the actual
selected console instance and disables AutoCheck.

## Confirmed Python command-generation repair

The original enabled pilot passed its version/ASCII paths but lost CR from a
CRLF command containing Unicode, quotes and shell metacharacters. Native command
execution retained the exact bytes. The disabled configuration passed both
version and token-denial cases. This failed attempt is retained as
`langflow-auto-login-command-pilot-20261120T155926`: **119 files**, manifest
`54d68f08ce97e90302da54539aeaba5a06c92cbb2418efeca581c8a89b296ffa`.

Independent generation through real CPython 3.14.6 confirmed that `python/exec`
embedded unsafe command strings in raw literals. Physical newlines, terminal
backslashes and overlapping closing quotes could change the command or produce
invalid Python. The identical final 21-case suite changed from **12 failures to
zero**. Twenty cases explicitly substitute Popen only to collect the real
interpreter's resulting argument; a separate real-Popen/file control independently
reproduces CRLF loss and verifies the repair, including waiting for the child.
The command option remains unchanged. Ordinary literal paths are retained and
unsafe inputs use the existing compressed argument fallback.

The focused repair is commit `a72f8aa7f0a`.
Its 175-file evidence capsule is `python-exec-command-bytes-20261120T162024Z`,
manifest `0e574050da2b0df84dafd722d501f9a0d4188528e2ef03f2667ec6de2a5358e1`.
Python 2.7/3.4 and Windows are not runtime-qualified by that worker.

The unchanged real command pilots then pass **4/0** on stock Python 3.12.12.
All original declared inputs differ only in the repaired payload source, and
the complete 81-byte CRLF/Unicode result matches the native control. The replay
is retained in `langflow-auto-login-payload-fixed-pilot-20261120T162338`:
**151 files**, manifest
`83793345e3825d14d3372d25c8fd1286ab76dc2071d0de926c2d03e91f1fc5cd`.

## Default-session defect

An independent `exploit/multi/handler` session uses the same staged Python
family outside the vulnerable endpoint. It reaches the ready event, performs a
real public file-API proof, matches its persisted session metadata, closes and
restores the original target process/TCP baseline.

The first exploit selection omits TARGET and PAYLOAD. Actual session metadata
confirms `python/meterpreter/reverse_tcp`; no explicit payload choice is
substituted for that default path. The default session performs its UID 1000
file proof and the backend remains responsive while it is open. After public
shutdown, the callback closes but the same PID **531**, birth **21358511**, changes
from state S to Z beneath backend worker **49**. The independent native session
PID **444** disappears normally. The process-baseline failure prevents the
repeat; zombies are not whitelisted and the backend is not signalled.

The retained run is **two examples / one failure, zero pending**, with the native
case passing. Its 106-file capsule is
`langflow-auto-login-owner-zombie-20261120T164131`, manifest
`68d119a6c19850d4359f1bc346f7383c89382293837f498a659646bce077ec6e`.
A separate worktree extracted the existing authenticated execution boundary into
`Msf::Payload::Python.create_exec_process_stub`. It runs the exact UTF-8 payload
source in a separate interpreter and waits in a daemon thread to reap it. The new
helper requires Python 3.5 or newer and leaves existing helper APIs unchanged.
The original lifecycle candidate is `187b322a7dd`; the final integration is
`892db16f2a4`, including the option/lint corrections described below.

The final identical local owner suite has nine owned cases plus seven support
cases: original three failures, candidate zero twice. The forked process control
independently records original Z state; nonforking original execution blocks its
validator. The candidate returns promptly, isolates/reaps its interpreters and
leaves proof processes absent across repeats. Actual Python command execution
retains quoted CRLF output. HTTP/token/loot and probe payloads are explicitly
doubled; the real process controls use host CPython 3.14.6. Helper tests pass
14 owned plus seven support cases; authenticated tests pass four plus seven.
The 314-file capsule is `langflow-auto-login-session-lifecycle-20261120T170029`,
manifest `7a8803af2c07a08d6fee790ed966aaf2acfba1592e69be2642e05cbe89e2e583`.
The third original unit failure is the boundary's `@exec`/None decorator error;
real Langflow catches that error. It does not establish another command-byte bug.
The worker verified four inherited lint offenses against the original files.
The maintained integration resolves them: the shared helper gains its missing
module comment, the redundant port registration moves to DefaultOptions with
the same effective 7860, and Framework chooses the payload automatically.
An independent chooser probe and real default replay both select the original
staged Python Meterpreter. The corresponding unit checks the target/port and
absence of a forced payload; no compatibility exception suppresses lint.

The first real candidate default session then passes proof and full cleanup. Its
repeat initially stops in a fixture endpoint lookup before invoking the module.
The same run's authenticated counterpart regression passes **10/0**, with six
used/closed shell and staged Meterpreter sessions, including disabled forking.
This 178-file capsule is `langflow-auto-login-lifecycle-fixed-first-20261120T170450`,
manifest `77130655a354a64437437456747c768dc17bf3fcc9945945620554fafb3b39c5`.

After correcting that lookup, the complete pilot passes **6/0**, with zero pending
or outside errors. Actual defaults are omitted on the first owner selection; the
repeat's selected console object ID matches. Both owner PIDs **514 and 580**
disappear, callback connections close, unique reporting rows close and the full
original target process set is restored. Command-byte and disabled-auto-login
profiles also pass. Its 186-file capsule is
`langflow-auto-login-complete-pilot-20261120T171108`, manifest
`731d4225463482934a00f0a657b11fda8a20e9f150fd5127921412d07dc2b550`.

## Setup failures retained separately

The first session fixture returned `:0` for its reporting database's published
port while that service had only an internal network. It stopped before RSpec;
no handler or exploit verdict was established. Giving the loopback-published
database a non-internal route allowed the next phase to proceed.

A later native handler passed but its dependent case was pending because an
example-local scalar readiness flag was not shared across RSpec examples. The
gate now uses the shared evidence hash and still requires successful native
readiness and cleanup. That two-example/one-pending attempt adds no qualification.
Its 101-file capsule is
`langflow-auto-login-native-handler-gate-20261120T163426`, manifest
`cadc182598f861aa79d1f9922528f03b528be6aa4a5343aa17a9b2103cccb50d`.

The console's projected options hash was empty.
Default-path evidence comes from the omitted input options and actual session
metadata, rather than that projection.

The reused authenticated verifier initially assumed a container console's
`module_endpoints` field. Host consoles have `endpoints` instead. Its fallback now
matches the existing common module-target helper. Recorded container-console
endpoints resolve identically; the host-console repeat executes and passes.

Promotion initially put the callback-host override in an included Ruby helper.
The RSpec context's directly defined method took precedence and raised
`KeyError: listener_host` before launching a native handler; the dependent owner
was withheld. The two command profiles separately passed 4/0. The run was stopped
and all 14 observed Docker objects were independently absent. Its 206-file
capsule is `langflow-auto-login-maintained-fixture-error-20261120T172625`,
manifest `b662bb653eb021d8b1cff6b7904aa90285a0d2aa92ec34bcdc754ff29c448c3c`.
The override now lives directly on the example group. That capsule also retains
an initial unit assertion's nil/hash mismatch, followed by the corrected 51/0
focused suite; the assertion failure is not product evidence.

A subsequent default replay passed 2/0. All four matrix native handlers passed,
but the no-fork owner case stopped at an assertion against the selected UI
object's datastore. Console action arguments belong to execution replicants
(`lib/msf/ui/console/command_dispatcher/exploit.rb`), so that UI value could remain
true while the action requested false. This 8-case/1-failure matrix is not
qualified. Its 209-file capsule is
`langflow-auto-login-console-observation-error-20261120T173045`, manifest
`2a093479624435b0d07921c429e613fbcd3ab4333ee91413fb1f73c63429f1cf`;
all 12 observed Docker objects are absent. The passive TracePoint now captures
the actual executing module's options. The assertion requires that actual value;
the selected UI object is still checked independently for repeat selection.

## Scope and lifecycle

New profiles use at most two capped test containers: the application, and a small
reporting database only for session phases. Commands and disabled-auto-login
controls need one container; Framework runs on the host. The existing authenticated
regression uses three capped containers including its console. Stacks run serially
under the shared heavy lock. Every completed phase removes its containers and
ephemeral networks; all **86** observed investigation objects are independently
absent, including resources from failed and interrupted setups. No running or
stopped containers remain in the final global inventory. Separately, the user's
explicit broader cleanup removed four unused connector containers outside the
test namespace; their exact IDs are independently absent. Routine test cleanup
remains scoped to created resources.

The module's original human Scenarios remain **911 bytes**, SHA-256
`1d744a5d04abdee5f082fa2a86d53d6ce3c2e9f5c8d23d545bb76b2e18a77932`.
Other releases, fixed-release behavior, architectures, TLS, prefixes, external
authentication providers and unexercised payload families remain unqualified.
No PR or external comment is part of this work.

## Self-review

- **Summary:** Ready for fork publication in the exercised paths; the broader module campaign remains active.
- **What looks good:** Independent native prerequisites, exact bytes/tokens, actual execution settings, repeated selection, original reporting rows and strict process cleanup all verify against unchanged inputs.
- **Concerns:** The release/platform/protocol limits above remain. Failed source and fixture attempts are preserved separately; none count as passing qualification.
- **Suggestions:** Use the short default profile routinely and the wider matrix for payload/process changes. Investigate other releases and remaining valuable owners separately.
