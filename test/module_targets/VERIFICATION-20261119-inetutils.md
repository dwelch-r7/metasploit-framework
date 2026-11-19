# Native GNU Inetutils Telnet execution, 2026-11-19

Three pinned profiles pass **33/0**, with zero pending or outside errors.
One owner and three profiles advance the cumulative record to **305 runtime
owners in covered paths, 627 qualified profiles and 4,435 historical functional
cases**. The broader campaign remains active; no PR is created.
The [profile guide](inetutils_telnet/README.md) provides guarded commands.

## Actual targets and paths

The app images install genuine Ubuntu packages from the immutable
`20260210T000000Z` snapshot with normal archive signature and TLS checks.
A checksum-pinned Ubuntu ca-certificates archive supplies bootstrap roots.
The normal packaged inetd, telnetd, login and PAM stack performs authentication;
no product handler or vulnerability is simulated. A separate PostgreSQL
container stores Framework reports. Both app listeners use ephemeral host
loopback ports. Base manifests, exact package versions and bootstrap checksums
are recorded in [releases.json](inetutils_telnet/releases.json).

| Profile | Distribution | Inetutils package | Cases | Used sessions |
| --- | --- | --- | ---: | ---: |
| `inetutils_telnet_bionic` | Ubuntu 18.04.6 | `2:1.9.4-3ubuntu0.1` | 11 | 4 |
| `inetutils_telnet` | Ubuntu 24.04 | `2:2.5-3ubuntu4` | 11 | 4 |
| `inetutils_telnet_fixed` | Ubuntu 24.04 | `2:2.5-3ubuntu4.1` | 11 | 0 |

Before and after each profile, independent native GNU clients establish actual
password login as UID 1001, incorrect-password rejection, root bypass
first/repeat, non-root bypass and absent-account rejection. Both the direct
listener and a bridge that splits server writes run these controls. Exact
file bytes/UIDs, sources, PAM configuration, account files and the main inetd
PID are checked. Normal login history is retained. The fixed package's ordinary
login works while the bypass is rejected. These versions are selected contrasts,
not a claim that every release boundary or later security repair is covered.
[GNU advisory](https://www.openwall.com/lists/oss-security/2026/01/20/2),
[Ubuntu package fixes](https://ubuntu.com/security/CVE-2026-24061).

The public owner runs through msfconsole. Paths include fresh/reused console
modules, root/non-root accounts, non-default terminal type/speed, literal
quotes/backslashes/newlines, split server writes and absent-account rejection.
Actual Bash shells and HTTP-fetch Meterpreter sessions each run twice on both
vulnerable profiles. The fixed profile rejects both families twice. Native TCP,
Bash callback and HTTP delivery/execution of a source-built harmless x64 ELF
calibrate prerequisites before owner sessions. No host dependency is installed;
the ELF prerequisite uses the existing NASM installation.

## Confirmed source defects and repairs

The original owner sends the payload when its seventh read contains Bionic's
`Last login` message. The inherited login regex then returns from connect and
the owner immediately disconnects. Native clients repeatedly execute exact
root/non-root proofs, while three original owner commands leave no proof.
The repair sends an encoded harmless nonce probe, waits for shell-produced
output rather than its terminal echo, then dispatches unchanged payload bytes.
It retains the existing negotiation sequence and bounded command completion.
The same sixteen focused examples change from **13 failures** to **16/0**.
The fixture uses seven exact captured incoming chunks and the real inherited
connect method; socket responses remain an explicitly modeled transport.

The first live repaired replay passes ten cases but exposes a second failure:
a Bash session registers and then reaches EOF before it can be used. Native
Telnet-client controls isolate the cause. Closing only the original Telnet
connection interrupts the foreground callback; a separate `trap '' HUP` prefix
lets the same UID 0 callback and PID continue after closure. The follow-up
sends that prefix only for enabled, non-None callback handlers, retaining
ordinary command signal behavior and the original payload write. The same
20-case suite changes from **one failure** to **20/0**. It includes a real POSIX
child-signal regression and no-handler/disabled-handler controls. Both source
repairs pass RuboCop and msftidy with no offenses.

The final native replay uses and closes both Bash sessions on both vulnerable
releases, and retains the original `UNRELIABLE_SESSION` metadata rather than
promoting reliability from this limited matrix.

## Setup and oracle failures kept separate

Preserved, unqualified attempts include absent base-image CA roots, HTTP
snapshot redirection to TLS, a base-image Perl version newer than its historical
APT snapshot, automatic native-client username substitution, negative responses
that closed before printing an error, and checking a proof before its pipe
finished writing. An initial bridge timeout injected EOF after successful
commands; removing that idle timeout produced the same exact successful
commands with no positive owner errors. No packet-boundary defect is established
by that experiment.

A cleanup assertion initially masked the real Bash EOF by trying to close an
already-absent session. The fixture now retains unqualified attempts and the
original failure. Another replay reaches **32/33**: an asynchronous Meterpreter `/bin/touch`
proof is immediately closed, and one expected file does not appear within the
bound. That completion assumption does not establish a module failure. The
local fixture uses an acknowledged Meterpreter filesystem write instead. Exact bytes/UID,
no leaked channels, native executable SHA and closure checks remain required.
The shared older helper is unchanged; its process-close assumption remains a
separate harness follow-up. These failures are not credited as source repairs.

## Final evidence and limits

Run `20261119T010956-5c3623` verifies **98 unchanged distinct declared inputs**,
**48 public owner calls**, **14,970 owner events** and **72 native controls**.
All **eight used sessions** have matching independent SQL records, expected
owner/payload, CVE-2026-24061 references and closed timestamps. Actual Meterpreter
process executable SHA-256 values match the generated served ELF bytes.
Proofs, fetched files, callback sockets, jobs and sessions are cleaned up.
All eight remote callback processes are absent after shutdown; no terminated
zombie state is needed to accept these closures.

All **156 memory/PID event captures are zero**. At most two capped containers
run: app 1 CPU/512 MiB/128 PIDs, reporting 0.25 CPU/384 MiB/128 PIDs. All **15
owned Docker objects** are independently absent afterward; the namespace is
empty and unrelated initial containers are preserved. Finished stacks are
removed immediately. Only recorded task-created objects are eligible for
cleanup, including unused containers older than an hour.

The local host is macOS 26.7.2 x86_64, Ruby 3.3.13 and NASM 3.02. Docker Desktop
29.9.3 runs Linux 7.0.14-linuxkit x86_64 with cgroups v2. Scope is these three
Linux package/configuration profiles, plaintext Telnet, and
`cmd/unix/reverse_bash` plus `cmd/linux/http/x64/meterpreter_reverse_tcp`.
Other releases, locales, login shells, architectures, TLS, external/disabled
callback handlers and staged or other payload combinations remain unqualified. Unit
negative controls do not establish those runtime paths.

New test Ruby is lint-clean. Module-doc tidy retains two inherited warnings
inside the **21,375 byte-for-byte preserved human Scenarios bytes**: trailing
space and the original missing final newline. No new tidy warnings are added.
No full local RSpec suite was run; local evidence does not qualify fork CI.

**Summary:** The recorded command/session paths and genuine fixed contrast pass.
**What looks good:** Independent native, SQL, executable hash and resource
checks accompany repeats and exact command bytes. **Concerns:** The explicit
untested paths, inherited documentation warnings and older shared proof helper
above remain limits. **Suggestions:** Continue the module queue and address the
shared helper separately; no PR is created.
