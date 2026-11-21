# Laravel token genuine fixed-release validation

The four freshly replayed token profiles pass **16/0**, including the new
genuine Laravel **5.6.30** control at **3/0**. Six unchanged shared session
profiles retain **12/0** with their current inputs and raw proofs re-audited.
The latest ten-profile set therefore passes **28/0**, with **25 real sessions
used and closed**. One new profile and three new historical cases bring the
campaign to **318 runtime owners, 674 qualified profiles and 4,791 historical
functional cases**. The broader module-inventory goal remains active; no PR is
created.

## Real packages and a shared recipe

The [fixed fixture](laravel_token_fixed/README.md) shares the vulnerable target's
pinned PHP 7.4.15 runtime, starter application and Dockerfile. A dependency-file
build argument selects the separate committed 5.6.30 project, lock and source
manifest. Its framework package is upstream revision
`38506212abdfe489f7ec914f9c43c77e3347aebe`. Composer 2.2.26 resolves the minimal
update; Composer 1.10.27 performs a clean installation in the metadata format
this old application actually consumes.

The complete locked package comparison changes only `laravel/framework`, from
5.6.29 to 5.6.30. The other **85 packages remain identical**. Of seventeen
installed source pins, thirteen remain identical; the project/lock and genuine
CSRF/cookie middleware account for the four differences. No vendor code,
application middleware, payload runtime or HTTP transport is patched.

Laravel documents [5.6.30 as a security release](https://laravel.com/docs/5.6/upgrade#upgrade-5.6.30)
that changes cookie serialization. The tested package's normal CSRF path avoids
object deserialization. Qualification below depends on actual native controls
and owner behavior, rather than the release label alone.

## Native positive before HTTP denial

An initial native-only pilot proves six ASCII/Unicode/quoting/CRLF controls
across working gadgets 2, 3 and 4. For each control:

1. Reflection instantiates the installed classes; PHP serializes them and the
   installed Laravel Encrypter creates the token. The physical proof stays absent.
2. The installed Encrypter's normal local default-decrypt API deserializes that
   token. Object destruction executes exact file bytes as UID 33 and emits a
   standalone output marker. The decoded class and token SHA256 are recorded.
3. The proof is removed and its absence checked. The **same encrypted token**
   is submitted to the genuine HTTP middleware with the same application key.
4. HTTP returns the captured **419 Page Expired** response, emits no execution
   marker and leaves the proof absent.

All six pilot controls pass. Seventeen installed source hashes match before and
after. The native stack is removed before functional tests begin. These probes
are prerequisites and add no separate qualified profile or historical cases.

The committed functional profile repeats the local-positive/same-token-denial
gate nine times: three readiness controls and three before each of two actual
owner invocations. This demonstrates usable gadgets, exact command bytes and
the correct encryption key independently of HTTP denial. Gadget 3 executes and
then raises its captured `dispatch() on string` Error during object destruction;
the structured native result retains that error and the exact physical proof.
It is not represented as an error-free local API operation.

## Actual owner and companion results

| Fresh profile | Examples/failures/pending | Used and closed sessions |
| --- | --- | --- |
| `laravel_token` | 9/0/0 | 0 |
| `laravel_token_fixed` | 3/0/0 | 0 |
| `laravel_token_env` | 2/0/0 | 0 |
| `laravel_token_perl` | 2/0/0 | 7 |

On the fixed target, the real Framework check attempts all four gadgets and
returns reason-bearing **Detected**, without claiming execution. Its four POST
responses are 419. The actual command owner runs twice on the same selected
console object. Each invocation attempts all four fallbacks; all eight POSTs
return 419 and neither invocation creates its physical proof. Native local
positives using those exact commands precede each invocation. This qualifies
the stated owner path's denial; it does not assert a broader Safe classification.

The vulnerable 5.6.29 companion still independently proves three working HTTP
gadgets and the hardened Faker denial. Its real check continues past reflected
gadget-1 text to actual gadget-2 output. Exact command bytes, wrong/short keys,
debug-page discovery and repeats pass. Ten positive owner observations still
contain three executions each, exposing the legacy non-session fallback behavior.
The genuine static `.env` discovery profile also passes both cases and repeats
without using the debug-page fallback.

The default Perl companion independently calibrates its handler, then verifies
default and explicit repeated owner selection on the same console object. Both
owner invocations again create three callbacks. Every one of the six owner
sessions and the native handler session creates physical UID-33 proof, exposes
its persistent PID/birth and socket, and owns an original open reporting row.
Public EOF closure removes all processes/sockets, closes every original row and
restores the complete baseline. The production fallback loop is unchanged.

The six retained profiles are `ignition_bash`, `invoiceninja_bash`,
`invoiceninja_php_shell`, `invoiceninja_fetch`, `invoiceshelf_bash` and
`invoiceshelf_php_shell`. All their declared inputs remain current. Their native
controls, eighteen physical session proofs, original row closure and full
process/socket restoration are re-audited from raw evidence. They are not
described as new executions or counted again as new campaign cases.

## Inputs, resources and cleanup

Independent audits reconcile **121 current declared inputs** for the latest ten
profiles. The four-profile wrapper freezes all inputs throughout its run and
contains no private runtime override. Its **20 memory/PID event captures are
zero**; the six retained profiles add 52, making **72 qualified zero captures**.

Fresh stacks run serially with at most **two capped containers**. Each application
uses 1 CPU, 512 MiB memory/equal swap and 128 PIDs. Perl's reporting database uses
0.2 CPU, 128 MiB/equal swap and 64 PIDs. Two separate dependency preparation
containers each use 1 CPU, 768 MiB/equal swap and 128 PIDs and are removed as soon
as they finish. Published application/database ports bind only to loopback.

All nine functional-phase Docker objects, two native-pilot objects and two
installer containers are independently absent: **thirteen new removals**.
Rechecking the prior 312 verifies **325 absent recorded Docker objects**. The
final global inventory includes stopped containers and is empty; no owned
ephemeral network or volume remains. No new tool/agent helper container is
started. Namespace records and ensure cleanup cover every temporary stack.

Three changed/new Ruby helpers/specs pass RuboCop. The new PHP native branch is
executed on the actual PHP 7.4.15 consumer. Production module and focused unit
inputs remain byte-identical to the preceding publication; that source suite's
last execution was 12/0 and it is not rerun here. Module-document tidy retains
the same two inherited warnings with zero new warnings. Its human Scenarios
remain 1,030 bytes with SHA256
`6bb0ad080ff6a8fd310e25cc1c78f5e5d3406c5bde4d1350d06954f41f669385`.

## Retained evidence

Local immutable capsules under `/Users/dwelch/.codex/reports/` contain frozen
inputs, raw native/owner output, independent audits and exact cleanup receipts.
The maintained capsule also records the current-input reconciliation for the
six retained profiles and points to their original raw session capsule.

| Capsule | Files | SHA256 manifest |
| --- | --- | --- |
| `laravel-token-fixed-native-20261121t024714` | 190 | `20073b35b9932e4552d976efc099c573e8c09f4909d1e571b89be896152e0053` |
| `laravel-token-fixed-maintained-20261121T025017` | 357 | `2b4a1dfafb4bbf40d0faf65a5cee3addf38fcfcd0d4c842778971507b87f90c7` |

## Self-review

**Summary:** A genuine fixed package and independently usable native gadgets
qualify three new denial cases, with all affected vulnerable profiles replayed.

**What looks good:** Only one locked package changes. Physical native positives,
identical-token HTTP denial, actual owner calls and current input fingerprints
separate a real fixed consumer from a broken setup. Every new session closes.

**Concerns:** The 5.5 branch, other releases and payloads remain unqualified.
Duplicate owner callbacks and earlier native PHP Meterpreter/Ignition log-state
failures remain recorded for investigation. A passing fixed-token profile does
not settle those failures.

**Suggestions:** Add genuine 5.5 release-boundary controls and investigate the
legacy callback loop separately, then continue other valuable feasible owners.
