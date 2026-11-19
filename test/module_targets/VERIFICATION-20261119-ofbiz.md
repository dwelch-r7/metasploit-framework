# Native Apache OFBiz verification — 2026-11-19

Four release profiles pass **100/0** functional cases. The older 17.12.01
profile retains **25 examples / 11 failures** as a diagnostic; it is excluded
from qualified totals. The batch adds two execution owners and four qualified
profiles, reaching **307 runtime owners in covered paths, 631 qualified profiles
and 4,535 historical functional cases**. The broader goal remains active.
No PR is created.

## Exact final replay

| Profile | Examples/failures | Used and closed sessions | Qualification |
| --- | --- | --- | --- |
| 17.12.01 | 25/11 | 4 | Retained diagnostic |
| 18.12.09 | 25/0 | 10 | Qualified |
| 18.12.10 | 25/0 | 4 | Qualified |
| 18.12.14 | 25/0 | 4 | Qualified |
| 18.12.15 | 25/0 | 0 | Qualified |

All results come from one final serial replay of the committed candidate inputs,
not a combination of earlier pilots. There are no pending examples or errors
outside examples. 85 recorded input digests agree across profiles and
match the tested files. The four qualified profiles contribute 18 used sessions;
the diagnostic contributes four more, counted separately. The fixed release
opens no session. Session proofs use real filesystem or shell operations,
native PID/UID checks, matching delivered ELF bytes, persisted Framework records,
closed TCP connections and independently absent remote PIDs after closure.

The XML-RPC owner covers commands, Bash and x86/x64 Linux droppers on 18.12.09.
ProgramExport covers commands, Bash and x64 HTTP-fetch Meterpreter on vulnerable
releases. The tests repeat execution on the same console module, separately
exercise a fresh instance with AutoCheck disabled, preserve literal quote,
backslash and newline bytes, and test missing paths or closed local ports.
ProgramExport registers no TARGETURI option; its fixture uses the supported root
path. SOAP execution is not qualified by removed-endpoint refusal tests.

Reproduce one release or the complete serial matrix using the
[profile guide](ofbiz_17/README.md). The exact final run is
`20261119T032255-7897a4`.

## Native controls and provenance

The profiles pin Linux AMD64 image manifests and compare relevant container
source files with official archives whose published SHA-512 checksums were
verified. The documented Vulhub host-header change is included in the 18.12
reference hashes; 17.12.01 has Gradle bootstrap/plugin recipe edits. These are
explicit lab differences. The image build's historical Git revision is not
available in its metadata. Archive, source and recipe references are recorded in
[releases.json](ofbiz_17/releases.json) and the shared guide.

Before and after every profile, independent controls verify ordinary application
login and entity access, denied guests/absent accounts, native XML-RPC/SOAP ping
or endpoint removal, and genuine ProgramExport exact-byte writes or refusals.
Valid serialized Java Strings calibrate XML-RPC extensions independently of
exploit gadgets. The 17.12.01 and 18.12.09 controls each pass 15/0 per phase;
other releases each pass 13/0 per phase. Source hashes, the original Java
PID/start time and proof-path state stay unchanged.

## Focused repairs

Five focused source repairs are retained as separate commits:

| Problem | Native evidence and regression |
| --- | --- |
| XML-RPC reports a nonexistent HTTP404 path as vulnerable old OFBiz | Independent GET/POST404 controls; the same initial suite changes from 17/5 to 17/0. Gadget selection and request methods remain unchanged. |
| ProgramExport corrupts quoted/backslash/newline commands | The original owner fails while genuine ProgramExport preserves the same shell bytes; exact target Groovy 2.4.13 regressions change from 8/4 to 8/0. |
| ProgramExport prints failure after successful execution | Native proof files contradict the warning; the reporting suite changes from 11/2 to 11/0. |
| SOAP prints execution success for HTTP200 errors | Rejected-ObjectBean and removed-endpoint replies produce no command proof; reporting regressions change from 7/3 to 7/0. |
| XML-RPC prints execution success for a removed endpoint | Native 18.12.10 returns HTTP200 with Unknown request and no command proof; the expanded suite changes from 21/3 to 21/0. |

Delivery messages now describe only the observed HTTP response. They do not
claim that a command executed. The parent worktree passes **39/0** focused
examples, with no pending or outside-example errors. Groovy semantic cases use
the exact exported target jar and an existing JDK8. Windows is checked only at
literal/dispatch boundaries; native Windows execution remains untested. No host
or Framework dependency is installed.

Syntax checks pass. RuboCop and msftidy retain six inherited default-payload/
duplicate-RPORT warnings across the XML-RPC and SOAP owners; there are no new
source, spec or helper offenses. All three module-document tidy checks pass,
and their existing human Scenarios suffixes remain byte-identical. The full
RSpec suite is not run.

## Retained failures and setup corrections

On 17.12.01, native controls establish that XML-RPC is available and manual
commands work, but automatic detection returns Unknown. Five strict detection/
automatic-execution cases fail. Native SOAP ping also works, while the real
object filter rejects the module's ROME ObjectBean. Six strict SOAP execution
cases fail. An empty-input Vulnerable result does not prove gadget compatibility.
These are retained investigations, not passing profiles.

The first 18.12.09 pilot is **23/8**, unqualified. Seven fixture failures come
from supplying an unregistered ProgramExport TARGETURI; two cleanup assertions
mask that primary failure. The fixture correction uses its supported root path,
closes interrupted console-owned sessions and preserves the original error.
One genuine failure is the SOAP execution-success claim. Native controls pass
before and after. Six used XML-RPC sessions remain evidence; two other callbacks
are not counted as used sessions.

The corrected pilot is **22/0** with ten used/closed sessions. Subsequent review
separates fresh disabled-AutoCheck cases so failed automatic detection cannot
hide manual coverage. A later 25-case matrix exposes the XML-RPC false success
on 18.12.10. All five profiles are replayed after that repair; earlier attempts
are preserved without inflating qualified case totals.

Other setup-only records include a private check-driver path typo, an archive
helper selecting a nested build.gradle template, and a guard refusal while
static checks still held the shared lock. The lock refusal creates zero
containers. Root archive extraction is corrected; native source-hash sets
exclude build.gradle and remain valid. No setup failure supplies a module
verdict. TracePoint filtering is moved before path expansion to reduce observer
overhead; owner and network methods are never replaced in the functional run.

## Resource ownership and remaining scope

Stacks run serially with one 1.5-CPU/1536-MiB app and a smaller reporting database.
The common worktree lock prevents overlapping heavy pipelines. The final audit
checks 540 resource-event captures with no memory or PID-limit events,
and independently verifies removal of all 25 owned Docker objects.
At most two task containers exist at once. Finished stacks are removed
immediately; unused task-created containers older than one hour are also subject
to removal. Cleanup uses namespace labels, recorded IDs and Compose ownership.
The namespace finishes empty and unrelated initial containers remain present.
The temporary Groovy-export container is never started and is removed immediately.

Windows targets, default Python-SSL payloads, staged Meterpreter, other releases
and deployment layouts remain unqualified. A published 13.07.03 archive has been
verified for possible legacy SOAP work, but no legacy build or runtime test has
run. The 15.12 image label is not established as a published Apache release.

The prior read-only CI observation window ends at 03:44 UTC with 129 successful
workflow runs, two failed runs and nine queued/running. The older
[pgAdmin](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44285946744)
and [namespace](https://github.com/dwelch-r7/metasploit-framework/actions/runs/44308950831)
Meterpreter workflows report filesystem acceptance timeouts; their cause is
unverified. They precede this batch. Local native qualification does not establish
CI checkout, build or installed-runtime coverage for a new push.

## Self-review

**Summary:** Five reproducible release labs qualify two execution owners while
preserving a strict legacy diagnostic and all earlier failed attempts.

**What looks good:** Independent native controls, exact byte and session proofs,
focused before/after regressions, unchanged tested inputs and owned cleanup.

**Concerns:** SOAP execution and 17.12.01 automatic XML-RPC detection remain
unqualified. Native Windows and unlisted payload paths require separate labs.
The older CI timeout causes remain unverified.

**Suggestions:** Investigate an authentic legacy SOAP-compatible release and
continue the feasibility queue; do not treat registered profiles as passing.
