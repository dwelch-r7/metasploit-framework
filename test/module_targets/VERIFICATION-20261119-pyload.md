# Native pyLoad command and Python execution, 2026-11-19

Four pinned vendor profiles pass **59/0**, with zero pending or outside errors.
Two owners and four profiles advance the cumulative record to **304 runtime
owners in covered paths, 624 qualified profiles and 4,402 historical functional
cases**. The broader campaign remains active; no PR is created.
The shared [profile guide](pyload/README.md) provides guarded setup commands.

## Actual targets and covered paths

Unmodified LinuxServer Linux amd64 images run their normal S6 entrypoint and
pyLoad as UID/GID 1000. The selected application sources match the corresponding
PyPI wheels. The real Click'N'Load addon proxies port 9666 to the primary web
server on port 8000. Both listeners use ephemeral host loopback ports. A separate
PostgreSQL container stores Framework reports; no Framework or host dependency
is installed by the fixtures.

| Profile | Release | Cases | Used sessions | Native distinction |
| --- | --- | ---: | ---: | --- |
| `pyload` | 0.5.0b3.dev30 | 18 | 10 | Both original pyimport and sandbox-escape primitives work |
| `pyload_dev31` | 0.5.0b3.dev31 | 13 | 2 | pyimport blocked; sandbox escape still works |
| `pyload_dev85` | 0.5.0b3.dev85 | 16 | 6 | Sandbox escape through the primary listener and CNL proxy |
| `pyload_dev87` | 0.5.0b3.dev87 | 12 | 0 | Both primitives blocked; ordinary encrypted-link collection works |

The first two images use Python 3.10.9/Alpine 3.17.0; dev85 uses Python
3.11.10/Alpine 3.19.4 and dev87 Python 3.11.11/Alpine 3.19.7. All use Js2Py 0.74.
The dev87 contrast therefore exercises the vendor's Object.getOwnPropertyNames
wrapper without changing to the Python 3.12 dukpy engine. Image digests,
LinuxServer revisions and selected source checksums are in
[releases.json](pyload/releases.json).

Before/after native gates verify the real login UI, valid/invalid authentication,
authenticated/anonymous API access, native Host restrictions and CNL proxying.
Real AES-CBC submissions create exact package/link rows in the collector; the
authenticated API deletes only those packages and a second submission works.
Independent injection controls require exact nonce bytes and UID 1000, not an
HTTP 500 alone. Sources, configuration, users, selected database state and the
main application PID remain unchanged.

The public owners are invoked through msfconsole. Covered paths include checks,
AutoCheck, disabled AutoCheck, reused module instances, exact quoted/backslash
and multiline commands, and the original module's command, Python and Linux
dropper targets. Actual sessions cover command-adapted Python Meterpreter,
direct Python Meterpreter and command shell, Bash, x64 Meterpreter and x86 shell
droppers. Each selected family repeats without AutoCheck. Native assembled
executables calibrate x64/x86 execution first; a separately generated x86 shell
also executes commands before the relevant owner cases.

## Confirmed defects and repairs

The 2024 owner's Host header incorrectly used the destination RPORT. The native
primary listener instead accepts the literal `127.0.0.1:9666`, independently of
the mapped destination port. The original owner returns Safe/HTTP 403 despite
the native primary-listener RCE control succeeding. The focused repair retains
RPORT for the connection and uses the vendor-accepted Host. Four routing cases
fail twice before the fix and all pass afterward. The mismatched flashgot
advisory is also corrected to the sandbox-escape advisory
[GHSA-r9pp-r4xf-597r](https://github.com/pyload/pyload/security/advisories/GHSA-r9pp-r4xf-597r).

The same owner's legacy regex string obfuscator corrupts literal newlines and
trailing backslashes. A real long command repeat also fails inside
`pyjsparser.std_nodes.node_to_dict` with a recursion-depth error after expansion
into string expressions. The repair serializes command data as one ASCII JSON
literal after obfuscating the escape chain, preserving randomized identifiers
and caller-owned strings. The unchanged thirteen-case regression has seven
failures before the repair and passes **13/0** afterward. Native multiline
commands and the previously failing long Meterpreter repeat now pass.

The original owner's direct Python Meterpreter target raises
`NameError: EXPORTED_SYMBOLS is not defined`. Js2Py invokes builtins.exec from a
function, so payload definitions and their global lookups use different
namespaces. The helper now executes with a fresh real Python globals dictionary
created inside Python, with `__name__` set to `__main__`; target 2 reuses it.
Five focused examples have four failures before the change and pass **5/0**
afterward. These use an explicitly disclosed Python bridge model. Independently,
the unchanged vendor application reproduces the decorated-function error and
the repaired entrypoint succeeds twice with exact exports, nonce and UID. Real
direct Meterpreter first/repeat then pass in the complete suite.

A failed shell bootstrap also exposes a Framework handler defect: the pending
connection is never released, and the extended wait can remain blocked beyond
WfsDelay. The repair releases registration accounting in ensure and wakes the
completion condition while preserving the original grace period, successful
registration and explicit interruption. The unchanged regression changes from
**19/7** to **19/0**; thirty existing TCP/UDP/HTTP handler examples also pass.
Two live intentionally invalid shell paths now trigger bootstrap EOF and return
within the declared bound, leaving no session, job or staged payload file.

Earlier setup/oracle failures remain sealed and unqualified: the wrong API
deletion keyword, a TXT URL that activated a real container decryptor, counting
an S6 startup wrapper as a second server, inspecting the console module instead
of the execution replicant, inline option quoting and checking staged-file
removal before session shutdown. A stale generic CMD also became an invalid
executable path when switching to the x86 shell payload; the fixture now resets
that payload's CMD to `/bin/sh`. None of these is attributed to a module fix.

## Final evidence and resource lifecycle

Run `20261118T234048-3dae67` retains **68 unchanged distinct declared inputs**,
84 public owner calls, 620 owner events, 104 owner HTTP exchanges and 136 native
HTTP controls. All **18 used sessions** have matching SQL session records and
closed timestamps. Vulnerability records retain the expected CVE references and
the corrected GHSA. Droppers verify actual executable SHA-256/UID while running,
then file removal after remote shutdown. Proof files and sockets are removed.
Two direct Python Meterpreter children reach terminated `Z` state before stack
teardown; this is accepted as process exit, not a claim that the owner reaps them.

All **268 memory/PID event captures are zero**. At most two capped containers
run: app 1 CPU/768 MiB/128 PIDs and reporting 0.25 CPU/384 MiB/128 PIDs. Core
dumps are disabled for the intentional invalid-payload control. All **24 owned
Docker objects** are independently absent after the replay, and the task
namespace is empty. Finished stacks are removed immediately; only task-created
objects are eligible for cleanup, including unused containers older than an
hour. Unrelated initial containers were preserved in this final replay.

The local platform is Docker Desktop 29.9.3, Linux 7.0.14-linuxkit x86_64 with
cgroups v2, on macOS 26.7.2; Framework uses Ruby 3.3.13. Scope is the four named
Linux releases and recorded payload families. Other application versions,
platforms, locales, TLS/proxy modes, engine variants and broader payload
combinations remain untested. The four releases do not establish every release
boundary or every possible sandbox escape.

Changed test Ruby has no lint offenses. Whole-owner checks retain each module's
existing duplicate-RPORT offense; the handler retains the same 34 inherited
offenses. No new offenses are introduced. Module-doc tidy passes and all
**6,403 bytes** of the original human Scenarios remain unchanged. No full local
RSpec suite was run; local evidence does not establish fork CI execution.

**Summary:** Both owners pass the recorded check/execution/session paths and
fixed-release contrasts. **What looks good:** Independent native, SQL, hash and
resource checks accompany the public calls and repeats. **Concerns:** The
inherited lint and terminated-child states above remain explicit limits.
**Suggestions:** Continue the pending module queue; no PR is created.
