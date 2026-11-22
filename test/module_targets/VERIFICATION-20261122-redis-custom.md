# Redis default compiled-extension qualification

The [compiled-extension profile](redis_replication_custom/README.md) passes
**two examples, zero failures/pending/outside errors** on genuine Redis 5.0.14
x64/Alpine. A native control and two owning Meterpreter sessions are actually
used and closed. The owning runs leave `CUSTOM`, TARGET and PAYLOAD untouched;
the second reuses the selected console module. Selected Redis state is restored
after each run.

## Native failure isolation

The canonical Linux Framework compiler builds the real SDK, and the pinned
musl Redis target loads it. Compilation, ABI identity and a successful load
alone do not establish raw payload execution.

The independent native probe first executes identical NASM bytes in an RX
mapping twice, writing exact quoted Unicode/CRLF bytes as UID 999. A separate
compiled C Redis command writes the same bytes twice. The original SDK loads
but its raw-buffer command creates no marker, while Redis remains responsive.
The server stack remains non-executable after loading a library requesting an
executable stack. No owning module call is made on this failed prerequisite.

A corrected rendered-C regression independently validates its complete bytes
and captures the original SDK child receiving `SIGSEGV`. It also demonstrates
that `wait(NULL)` can reap an unrelated child. This confirms SDK defects rather
than treating a failed target setup as a module verdict.

The frozen genuine Redis probe is replayed with the same driver, C control,
bytecode, compiler image and target. Only `module.erb` and the SDK Makefile
change. The candidate writes the raw marker twice and returns `OK` both times;
the independent controls still pass. Original runtime:
`native-20261122T083040`; candidate: `native-20261122T084217`.

Earlier setup failures remain separate: a duplicated shell argument prevented
one compiler launch; a root-owned Docker copy prevented another fixture cleanup.
Both were corrected and their exact resources removed before the frozen pair.
An exploratory host assembly generator also supplied incomplete bytes. Its
initial signal claim was withdrawn; corrected before/after evidence requires an
independent identical-byte execution control. None of those errors supplies an
owning-module failure or extra qualified case.

## Repair and regression evidence

The SDK copies its buffer into a dedicated mapping, enables execution while
retaining write access needed by self-modifying payloads, and releases the
parent mapping. It waits for its exact child, retries interrupted waits and
exits a child whose payload returns. Allocation, protection, fork, wait, child
status and release errors receive explicit Redis replies; cleanup errors retain
the primary failure. The Makefile no longer requests an executable stack.

The corrected frozen SDK spec has **22 examples**, including seven shared
framework examples: **14 failures before, zero after**. Actual rendered C uses
real POSIX calls on success, with injected failures for error contracts. It
covers raw execution, a self-modifying program, returning payloads, a second
invocation, unrelated-child ownership, interrupted waits and resource failures.
Linux compiler replay confirms these behaviors and canonical `GNU_STACK`
changes **RWE to RW**, with no compiler warnings. Parent integration passes
**22/0**; the unchanged owning Ruby spec passes **42/0** in the source worktree.

The new SDK spec and acceptance helpers are RuboCop-clean. The owner retains its
same two inherited findings, hardcoded default PAYLOAD and missing AutoCheck;
its inherited module-tidy exit 2 remains explicit. Ruby syntax, changed-document
tidy and diff checks pass. Existing human Scenarios remain byte-identical.

## Real default execution

Framework copies the actual SDK from the read-only repository into its own
writable tmpfs. Its normal compiler and the actual owner perform the builds;
no host source, generated C or shared library is written into the repository.
The target is the pinned official Redis 5.0.14 x64/Alpine image, running as UID
999 without a target password in an isolated lab.

Before owning calls, a separate C command proves native loader/file semantics.
The real SDK template then embeds the stock handler's already generated staged
`linux/x64/meterpreter/reverse_tcp` bytes with Linux forking enabled. Its direct
Redis command returns `OK`; public session APIs and independent physical
PID/birth/UID/file/fresh-response/shutdown observations prove a usable session
and physical closure. Native files/libraries, jobs and session registrations
are removed and selected state returns to baseline.

The owning check identifies the real service. Both owning executions show the
actual compiler path, default selection and a real Meterpreter callback. The
second reuses the selected console module. Each session receives the same
public and physical proof, then closes before state comparison. Generated C and
shared-library hashes are retained separately for native and owning builds.
Final runtime: `20261122T084321-b2cfa9`; its declared inputs remain unchanged.

## Coverage, cleanup and limits

This adds two cases and one profile for an already covered owner. All **739
previous inputs remain byte-identical**, including the bundled-extension path;
no broader compatibility replay is claimed. The retained set reaches **332
cases / 74 profiles / 775 current inputs**, **314 ordinary used/closed sessions**
and 21 separate source variants. The compiled profile contributes three actual
session lifecycles; standalone marker programs are not counted as sessions.

Standalone probes use one capped container at a time and remove the compiler
before starting Redis. The functional profile uses only a capped target/
Framework pair. All owned containers, networks, anonymous volumes and the SDK
tmpfs are removed promptly. Both Docker contexts finish globally empty,
including stopped containers; all **18 new / 1,157 recorded resource identifiers**
are absent and no new global volume remains. No image/cache pruning or daemon
restart occurs. The prior unrecorded Erlang pilot volume ID remains excluded
from exact-ID counts with its earlier set-based absence proof preserved.

State comparisons cover six CONFIG values, module list, selected replication
role/upstream fields and the `/data` entry set on an initially empty master.
Existing database contents, overwritten files, full process ancestry and peer
identity across restart/DNS changes remain unqualified. Explicit encoder
selection in a real owning run, native x86, authentication, replicas, other
releases and forking overrides remain separate. The self-modifying C regression
does not substitute for every encoder or target runtime. Systems denying
executable mappings receive the tested error contract; no such hardened target
is qualified here.

The complete valuable feasible-module goal remains active. No PR is created.

**Summary:** Repairs native-proven default SDK execution and child ownership.
**What looks good:** Frozen native comparisons, real C regressions and owning repeats.
**Concerns:** Encoder, target and existing-data preservation variants remain open.
**Suggestions:** Continue those paths and the full module inventory.
