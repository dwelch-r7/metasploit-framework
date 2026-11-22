# ProFTPD mod_copy native execution and cleanup

The [affected](proftpd_modcopy/README.md), [genuine fixed](proftpd_modcopy_fixed/README.md)
and [disabled-copy](proftpd_modcopy_disabled/README.md) profiles pass **16/0/0**.
The final original-source replay uses identical test inputs and retains
**16/5/0**. The sole changed runtime input is the owning module. Four source
defects are repaired in `858abf947ee`: early-failure FTP closure, refused-check
results, whole-program detachment and temporary PHP cleanup. No PR is created.

## Genuine targets and independent prerequisites

The shared recipe builds unpatched ProFTPD **1.3.5** from Debian's `.orig` archive
and official **1.3.5a** revision `379bdb0d413f9489768c29c3a36e7bc854c85395`.
No Debian patch series or vendor-code changes are applied. Archive checksums and
`mod_copy.c` hashes match [release pins](proftpd_modcopy/releases.json); build
configuration, loaded modules, binary hashes and runtime package versions are
retained. The affected archive checksum is also checked against its official
Debian source descriptor. The upstream [authentication repair](https://github.com/proftpd/proftpd/pull/109)
and [1.3.5a release](https://github.com/proftpd/proftpd/releases/tag/v1.3.5a)
provide the fixed-release provenance.

Python's standard FTP client independently proves incorrect-password refusal,
correct login, upload/download/delete and physical UID33 file ownership. Native
unauthenticated CPFR succeeds on 1.3.5. Genuine 1.3.5a requires authentication;
authenticated copying and PHP execution still work. `CopyEngine off` disables
copying while normal FTP and PHP health remain operational.

Positive controls exercise the complete `/proc/self/cmdline` to literal PHP
filename to web-directory chain. The real PHP 8.1.2-1ubuntu2.29 interpreter runs
ASCII and Unicode/quotes/CRLF commands with exact physical UID33 bytes. These
controls use no Framework implementation. Native callbacks also prove the
container-to-host route, Netcat and shell before owning callbacks. The maintained
profile generates the stock default Netcat program and independently executes
that exact program before each real owner invocation.

## Original and repaired results

| Profile | Original examples/failures/pending | Repaired examples/failures/pending |
| --- | --- | --- |
| `proftpd_modcopy` | 8/3/0 | 8/0/0 |
| `proftpd_modcopy_fixed` | 4/1/0 | 4/0/0 |
| `proftpd_modcopy_disabled` | 4/1/0 | 4/0/0 |

The original owner already passes repeated affected/fixed checks and four exact
finite-command executions. A refused FTP connection raises through Framework
and yields no reason-bearing CheckCode. Early copy failures return with their
actual local FTP sockets open. The original default Netcat payload opens a real
shell, but its multi-command program keeps PHP request streams open until the
HTTP timeout: the module reports execution failure despite the usable session.
FileDropper removes the web PHP file, while the unregistered temporary PHP file
survives actual session closure. Those two assertions fail one session example.

The repair catches the expected connection error as reason-bearing Unknown,
closes FTP in ensure, backgrounds the complete shell program with detached
streams and registers the temporary copy immediately after success. Owner-local
private FileDropper hooks shell-escape raw Unix paths, including literal
`$_GET`, without changing PHP requirements or shared-library behavior. Other
session/platform paths delegate to the existing helpers.

The candidate repeats checks, ASCII and complex command bytes on the same
selected objects. It obtains two actual cold-default Netcat sessions. Each
creates exact physical marker bytes as UID33, exposes its real `/bin/sh` PID,
birth and argv, responds to a fresh command and closes through public session
APIs. Both PHP files disappear before explicit test reset. Refused-connection
and unwritable-path controls, plus repeated fixed/disabled refusal, preserve all
configuration, foreign files, processes and live sockets. Resource-failure
counters remain zero.

The observer records original method paths/results and actual local socket
closure without replacing I/O. It retains socket references for inspection and
exact backstop cleanup. Thus these tests establish explicit closure on return;
they do not measure garbage-collector cleanup timing. Finite non-session
commands use `AllowNoCleanup=true`: their warnings and physical files are
captured before exact-directory manual reset, which is not automatic cleanup.

## Separate harness and fixture failures

The first original session example stops before invocation because the console
restores a prior generic payload. Standard `unset PAYLOAD` before back/use
corrects cold selection; the actual default is Netcat. A subsequent fixed-profile
attempt captures Docker's short-lived health-check PID in its initial baseline.
Its three owner examples are correctly withheld. Baseline acquisition now waits
for that exact health argv to disappear and for active sockets to close; later
comparisons retain every process and active socket. The final original matrix
passes all native gates and has no pending examples.

Initial source-unit FIFO buffering/reader races are retained separately. A
deterministic handshake corrects the fixture, then the identical frozen spec
reproduces **31/18 to 31/0**. Real descriptor, literal-file deletion and blocked
multi-command/stream controls supplement the native matrix. Root integration
passes **38/0**, comprising 31 focused and seven eager support examples. A
post-run hash-brace layout correction has identical Ruby VM ASTs and clean lint;
the tested/current hashes and equivalence proof are retained explicitly.

## Cleanup, publication and limits

Every phase runs one namespaced container capped at **128 MiB RAM/swap, 0.5 CPU
and 64 PIDs**, with read-only root and bounded tmpfs mounts. No extra capabilities,
privileged containers, database helpers or dedicated builder containers are
used. The native/functional phases create 32 objects, each independently absent
after cleanup; the campaign's 893 recorded objects are absent. Both Docker
contexts include stopped containers and are globally empty. All seven new host
callback ports are closed, with no host console or guard process remaining.
The user's one-off broader cleanup initially finds no unrelated containers.
No image/cache pruning or daemon restart is performed.

Syntax, source/doc tidy and Python/Compose checks pass. Five unique Ruby files
have zero new offenses: four inherited owner offenses remain (missing AutoCheck
and three redundant prefixes). Human-written module Scenarios remain unchanged.
The previous checkpoint's CI has eight passing checks; Verify fails at GitHub
checkout connectivity before build/test, and Meterpreter Acceptance is queued.
That infrastructure failure does not establish a source regression.

The passing retained set reaches **208 cases / 50 profiles / 560 verified inputs**.
Four more owning Framework sessions across original/candidate frames are used
and closed, for 181 ordinary sessions; 21 separate source-variant sessions remain
separate. Raw native callbacks add no separate functional example count. Exact
inputs, failed/corrected runs, source-unit evidence and cleanup/publication
receipts are retained in the private campaign evidence capsule.

This qualifies the recorded Linux/amd64, Ubuntu 22.04, PHP CLI-server and generic
command/default Netcat paths. Other PHP/web-server versions, payload families,
Unix platforms, release boundaries and distro/backports remain unqualified. The
full valuable feasible-module inventory goal remains active.
