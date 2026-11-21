# Ignition default sessions and retained log-state failures

The maintained session set passes **12/0** across six profiles in two serial
phases, with **18 real sessions used and closed**. The new `ignition_bash`
profile adds **2/0** historical cases and one qualified profile, reaching
**317 runtime owners, 670 qualified profiles and 4,775 historical functional
cases**. Five shared regressions add no duplicate campaign counts. The broader
module-inventory goal remains active; no PR is created.

## Real default and repeated Bash sessions

The [session fixture](ignition_bash/README.md) extends the genuine pinned target
from the [command investigation](VERIFICATION-20261120-ignition.md): Linux amd64,
PHP 7.4.15, Laravel 8.26.1 and Ignition 2.5.1. Thirteen installed application and
dependency source hashes match before and after. The production module is
unchanged, with SHA256
`594b2a9e7d4f7c2804d3e86d6f1d1cdf92000ed0eb9d27753b42d9dba8468462`.

An installed-class PHAR factory and genuine HTTP transport first prove exact
command bytes and UID 33. Native callback and stock Bash payload controls run as
`www-data`, matching the Apache worker. A real independent handler session gates
the owner. The first owner invocation omits both TARGET and PAYLOAD; Framework
resolves target 0 and `cmd/unix/reverse_bash`. The explicit repeat uses the same
selected console object with AutoCheck disabled. Trace events show two actual
owner exploit/PHAR/discovery calls and one reason-bearing Appears check.

Each session creates exact physical file bytes as UID 33, exposes its new PID
and birth identity with an established callback socket, and owns an open
reporting row. Public shell APIs request shutdown. Checks require process/socket
disappearance, closure of the original row, removal of the proof, a healthy
application and restoration of the complete original process set.

The session-only read-only Apache configuration keeps four genuine prefork
workers available and stable while an HTTP request holds its shell open. It
changes no application/vendor source. Shared session helpers now allow a
component-specific target map, execution user and default-option omission;
command payloads select the shell interpreter by payload family rather than by
a particular module's numeric target index. Existing consumers retain their
original defaults.

## Qualification and corrected oracle

| Profile | Examples/failures/pending | Used and closed sessions |
| --- | --- | --- |
| `ignition_bash` | 2/0/0 | 3 |
| `invoiceninja_bash` | 2/0/0 | 3 |
| `invoiceninja_php_shell` | 2/0/0 | 3 |
| `invoiceninja_fetch` | 2/0/0 | 3 |
| `invoiceshelf_bash` | 2/0/0 | 3 |
| `invoiceshelf_php_shell` | 2/0/0 | 3 |

The original six-profile phase records Ignition **2/1** and the five regressions
**10/0**. Its native and default owner sessions both work and close. The failure
is an invalid empty-log assertion: after shell shutdown the synchronous `system`
gadget resumes, and the installed LazyOption raises its observed
`Expected instance of PhpOption\Option` exception. The real UID-33 application
log is 7,263 bytes. That failed frame is retained and adds no qualification.

Only Ignition's helper and README change between runtime phases. The corrected read-only
oracle requires that single expected exception entry and its real source path.
The log stays in place before the repeated owner execution; no native control
resets or repairs it. Both successful owner sessions leave the observed
7,263-byte entry after shutdown. Unset TARGET in the default attempt and string
`"0"` in the explicit attempt are normal datastore values; the separately
observed resolved target index is 0 in both cases.

A fresh targeted replay passes **2/0**. All declared inputs for the five earlier
successful profiles remain current. The independent audit reconciles **87
current declared inputs**, actual callback identities, exact native PHAR bytes,
physical proof creation/removal, PID/birth identities, reporting closure,
selection reuse and final baseline restoration. No private payload runtime or
transport proxy substitutes for the normal owner.

## Retained native log-state failures

Broader log states remain unqualified. A native-only PHP probe invokes the real
installed solution and shows that `consumed` empties a short 44-byte input but
retains 8,192 bytes from 8,192- and 9,000-byte inputs. The same residual remains
for a captured 8-KiB log state from a genuine missing-log error. Thirteen source
hashes match before and after this isolated probe; it invokes no Framework owner.

Three separate native HTTP trials preserve their failures:

| Reset strategy | Observed native result |
| --- | --- |
| `consumed` | Both ASCII boundary cases complete exact PHAR conversion and UID-33 execution despite the residual; the captured error state fails quoted-printable conversion. |
| `dechunk` | The first ASCII case resets and executes, but post-trigger cleanup retains 7,632 bytes of archive/error data. |
| `consumed` followed by `dechunk` | Both ASCII cases complete; the captured error state still retains 8,192 bytes at reset. |

These are native setup/reset limitations, with no owner invocation or new module
verdict. They contribute no qualified profile or historical functional case.
Inputs, responses, partial physical proofs and cleanup receipts are retained.
The primary research's [log-reset approach](https://blog.lexfo.fr/laravel-debug-rce.html)
is tested against the actual pinned consumer; its description alone is not a
readiness gate. A reliable native control is still required before assessing
owner behavior on the failed captured state.

## Resources, checks and cleanup

Stacks run serially. Ignition uses one application capped at 1 CPU, 512 MiB
memory/equal swap and 128 PIDs, plus a disposable reporting database capped at
0.2 CPU, 128 MiB/equal swap and 64 PIDs. Existing Ninja regressions peak at three
capped containers. Ports bind only to loopback, resources use the task namespace,
and ensure cleanup removes finished stacks immediately.

All **52 qualified memory/PID event captures are zero**. The retained failed
session stack adds eight zero captures, making sixty across both session phases.
All **30 session-phase Docker objects** and **seven native-probe objects** are
independently absent. Rechecking the prior 229 objects verifies **266 absent
objects** in total. The final global inventory includes stopped containers and
is empty; no owned ephemeral network or volume remains. No new agent/tool helper
container is started in this tranche.

Four changed/new Ruby files pass RuboCop. The focused runner, network and endpoint
source checks pass **84/0**. Module source is unchanged. Module-document tidy
retains the same five inherited warnings with no new diagnostic. Its human
Scenarios body remains 1,218 bytes with SHA256
`383c03e0a902ccdddb3526949d246a70ea22d9120b8acfd465b08dc35cce9d75`.

## Retained evidence

Local capsules contain raw output, frozen inputs, independent audits and exact
cleanup receipts. The maintained capsule references the original failed session
frame and its five successful regressions; it does not replace that failure with
a blanket green claim. A companion capsule supplies exact native-probe inputs and
links the separate retained runtime capsules.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `ignition-default-sessions-maintained-20261121T005913` | 88 | `bd288d389d8fecc652032e698f0f911c7e5cde20198954f82b64c6fc6e02d2db` |
| `ignition-session-log-oracle-and-regressions-20261121T004550` | 285 | `ed8fb6143bec24452ccb51ff0d711f331b1116a6b14f49521f64ca337e03f3e3` |
| `ignition-native-log-boundary-20261121T002323` | 8 | `c5d1d036a023ba5debabb1cde678e0b3cf090de01b6b52f258742c8c9015d4c8` |
| `ignition-large-log-consumed-control-20261121t003129` | 99 | `e8216d18fc1f6c7d2180ac9cd5e5a2512f908f52ceca7056c362707c7885beb6` |
| `ignition-dechunk-reset-incomplete-20261121t004013` | 59 | `b34be5589787b9a251dd58ffdb5d0cd625ffbdd505438b9a99616e16ec83380d` |
| `ignition-combined-reset-incomplete-20261121t004305` | 92 | `38bb15402aa15c47ff15f1803fcb68952e61175d71b7730a7c6bd2c1c8493418` |
| `ignition-native-log-reset-inputs-20261121T010343` | 17 | `306771dc3654c7765d9002b646f189832bf09b3c348c160da2e5038e8e0c3966` |

## Self-review

**Summary:** Real default and repeated Bash sessions qualify one additional
profile without changing the production module.

**What looks good:** Native identity/handler controls, actual resolved defaults,
physical proofs, reporting closure and complete PID/socket restoration cover
execution and lifecycle. Passing regression inputs remain current across phases.

**Concerns:** Captured-error log reset, genuine patched Ignition packages,
Windows and other releases remain unqualified. Previously retained native PHP
Meterpreter failures in the shared consumers are unchanged and are not rerun.
The passing Linux fetch regression does not qualify those PHP families.

**Suggestions:** Establish a reliable native reset for the retained error state,
add genuine patched-package controls, and continue other valuable container-feasible
owners. Do not infer a working setup from an owner failure.
