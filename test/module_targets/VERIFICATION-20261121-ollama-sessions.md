# Ollama default Meterpreter and automatic library cleanup

The new separate session profile passes **2 examples / 0 failures / 0 pending**
in **151.78 seconds**, with **three real Meterpreter sessions used and closed**:
one independent stock ELF control and two actual owner runs on one selection.
Both owner libraries disappear through normal FileDropper cleanup before fixture
recovery, with `AllowNoCleanup=false`. The original vendor application and loader
remain unchanged. No production source changes or PR; the broader inventory
goal remains active.

The eighteen previous stated profiles retain 60 cases and twenty-two used/closed
sessions with all 204 declared inputs unchanged. The latest nineteen profiles
have **62 qualified cases**, twenty-five used/closed sessions, 214 current inputs
and 116 zero cgroup event captures. Historical coverage reaches **323 owners in
stated runtime paths, 689 profiles and 4,837 functional cases**. These are covered
paths, not fully qualified modules or completion of the entire inventory.

## Native readiness and normal owner behavior

[The session recipe](ollama_sessions/README.md) reuses the pinned official
Linux amd64 Ollama 0.1.33 target and independent native controls from
[the command tranche](VERIFICATION-20261121-ollama-rce.md). Local GCC library
loading, ordinary OCI model pull/show, exact traversal bytes and genuine API
runner execution must all work first. The resident observer prevents helper
execs or healthchecks from consuming an armed preload and faking API execution.

A native callback verifies the real route, UID zero, PID/birth and socket inode.
The existing Framework ELF helper wraps the actual stock Linux x64 stager from
a running handler. Physical ELF bytes, SHA256, class and machine match before
independent execution. Its session must write a root-owned proof, own the real
callback socket and original SQL row, respond to a fresh RPC and shut down
remotely. The full target process set must return to baseline before owner work.

The console independently observes normal defaults: target **0**, payload
**linux/x64/meterpreter/reverse_tcp**, depth **14**, `AllowNoCleanup=false`.
The first owner run omits target/payload overrides. The repeat uses the same
selected console object with AutoCheck disabled, proving setup is independent
of an earlier check. Each real Metasm-generated library equals its physical
bytes immediately before the module's own chat trigger. Passive traces record
the original FileDropper calls and actual physical library removal.

Each owner session then writes exact `ollama-session` bytes as root. Its PID,
birth value, socket inode and original open SQL row agree. Fresh RPC and public
Meterpreter shutdown precede PID disappearance and closure of that same SQL row.
All three final session/database IDs are **1, 2, 3**. Model aliases disappear;
processes, jobs, sessions and callback connections reset between attempts.
The source-registry listener refuses connections after every lifecycle; both
host callback and registry ports are independently closed at final cleanup.

## Cleanup state and failures retained

The constructor removes `/etc/ld.so.preload` before its payload child runs.
Mettle's later removal of that already-absent file returns an error, so
FileDropper retains **only its pathname** in the retry list. The actual library
is removed successfully, and independent resident reads prove both files absent.
The test requires that exact observed bookkeeping state; it does not confuse a
retry-list entry with a physical artifact or claim that the list becomes empty.
The second owner run still succeeds and cleans its new library.

Three raw frames are retained:

| Frame | Result | Interpretation |
| --- | --- | --- |
| `20261121T083856` | 2/1/0, one after-context error | Stock session passes; inherited 3-second HTTP override cancels the first owner pull at 3.005 seconds. Native pulls take about 3.07 seconds. A library remains; footprint retained before teardown. |
| `20261121T084338` | 2/1/0 | Normal HTTP timeout allows an actual owner session and physical library cleanup. An overstrict harness expects the retry list to be empty and stops before its proof/shutdown sequence. |
| `20261121T084707` | 2/0/0 | Correct physical/bookkeeping oracle; stock control and both owner sessions fully used, reported, closed and reset. |

The timeout override is removed, preserving the ordinary HTTP client's
20-second request default. Failure footprints are captured before narrowly
scoped resident recovery. Earlier stock controls and the partial owner observation
are retained separately; they do not inflate the final qualified session totals.
No production fault is established from these harness failures.

The application uses 1 CPU, 1024 MiB memory/equal swap and 128 PIDs; the disposable
reporting database uses 0.2 CPU, 128 MiB/equal swap and 64 PIDs. At most **two
capped containers** run, one serial project at a time. Finished/failed stacks
are removed immediately. All **nine new and 476 recorded Docker objects** are
independently absent. Global running/stopped containers, owned ephemeral
networks and volumes are empty. No images/cache pruning or daemon restart.

Sixteen fresh cgroup captures are zero. Four Ruby files pass RuboCop; Compose,
excluded acceptance discovery, documentation tidy and diff checks pass. The
original **1,588-byte human Scenarios tail** is unchanged, SHA256
`c225508d4c4b4a1721a8c1c4293719098b46efdb5dbb8b018717567f79f6844d`.
Automated captures do not provide human Scenarios. Other payload families,
releases, nonroot deployments and alternative model directories remain outside
this session profile.

Self-review summary: default session delivery and automatic physical library
cleanup are qualified in this recipe. What looks good: independent stock/native
controls, exact owner bytes and original SQL/PID/socket closure. Concerns: the
absent preload remains in FileDropper bookkeeping, and untested configurations
remain outside the claim. Suggested next step: broaden to an uncovered valuable
target rather than counting this subset as the whole campaign.

## Evidence

Immutable capsules under `/Users/dwelch/.codex/reports/`, each sealed with
`SHA256SUMS`, retain frozen sources, native HTTP/ELF controls, original console
output, lifecycle traces, physical proofs, SQL rows, resource counters and exact-ID
cleanup receipts. Failed frames are
`ollama-sessions-short-http-timeout-20261121T083856` and
`ollama-sessions-cleanup-oracle-20261121T084338`. The final capsule is
`ollama-sessions-maintained-20261121T084707`; private audit/qualification pointers
are in `tmp/ollama-sessions-feasibility/`. Local temporary paths are not repository
dependencies.
