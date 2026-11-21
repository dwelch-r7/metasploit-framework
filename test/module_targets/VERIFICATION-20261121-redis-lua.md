# Redis Lua package, command and default-session verification

Observed 2026-11-21. This qualifies the stated Ubuntu package/Unix Command paths;
the full valuable container-feasible module inventory remains active.

## Real target gates

One official Ubuntu image runs at a time as UID 101, pinned by registry digest,
with 128 MiB RAM/swap, 0.5 CPU, 64 PIDs, read-only root and bounded tmpfs. The
[profile documentation](redis_lua/README.md) includes the exact guarded commands,
images, lab authentication, native controls and explicit limits. These distro
packages dynamically link Lua; the existing upstream Redis profiles cannot
substitute for this vulnerability. Primary background is the
[researcher's explanation](https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce),
[Ubuntu advisory](https://ubuntu.com/security/CVE-2022-0543) and
[Debian advisory](https://lists.debian.org/debian-security-announce/2022/msg00048.html).

Two preliminary image probes identify `5:6.0.11-1` and `5:6.0.16-1ubuntu1`,
actual Redis/library hashes and UID 101. The former runs `id` through
`package.loadlib`; the latter blocks the `package` global while keeping Lua
arithmetic and direct shell execution operational. Both probe containers are
removed. Full functional profiles repeat the native gates independently:

- Real `redis-cli` PING/authentication, package/binary identity, arithmetic and
  invalid Lua precede any owning method. CLI exit zero alone is insufficient.
- Exact plain and quoted Unicode/backslash/CRLF commands run directly through the
  stock shell and real Lua with physical byte/UID proofs. Patched Lua denies the
  same command, while its direct shell positive still works.
- Checks repeat on one selected module; incorrect credentials recover. Missing
  Lua-library recovery, refused connections, AutoCheck on/off commands and
  patched repeated AutoCheck refusal retain distinct assertions.
- A native stock Bash payload session precedes two actual default owning sessions.
  Post-bootstrap session-open events gate reads. Fresh replies, actual file
  bytes, UID 101, PID/birth, graceful exit and two-peer socket closure verify use.
  The Bash payload's random FD is left untouched; native/owning family controls
  do not claim byte-identical independently generated random-FD payloads.
- Complete Redis configuration, exact serialized keys in databases0/2, all
  UID 101 processes and a foreign file preserve. Script-cache entries and runtime
  counters naturally change. Health helper exclusions are explicit; reparented
  payload children and half-closed callback sockets remain checked.

## Observed before and after

| Profile | Original examples/failures/pending | Repaired | Repaired seconds |
|---|---:|---:|---:|
| `redis_lua` authenticated 6.0.11 | 9/2/0 | 9/0/0 | 153.21 |
| `redis_lua_open` open 6.0.11 | 9/2/0 | 9/0/0 | 117.22 |
| `redis_lua_fixed` authenticated 6.0.16 | 6/1/0 | 6/0/0 | 47.67 |

Every frame has zero outside-example errors and verified Compose cleanup.
Original rich commands pass native same-command controls, then owning delivery
returns `ERR Protocol error: unbalanced quotes in request`. Original refused-port
checks raise `Rex::ConnectionRefused` and produce no reason-bearing CheckCode.
Both assertions remain enabled and pass against the repair.

The isolated source fix is commit
[`fbd896331764`](https://github.com/dwelch-r7/metasploit-framework/commit/fbd896331764b17896a220ca710dfaddb1e34bee).
It reuses the existing Redis RESP serializer with binary library/command ARGV
operands, avoiding inline/Lua quoting and the shared serializer's character-count
problem for these operands. Original raw socket reads/writes and response bytes
remain. Expected transport/auth-helper failures become diagnostic reason-bearing
Unknown results; disconnect is attempted on every check path. Programming faults
and user interrupts remain visible. Targets, payload defaults, options, shared
libraries and final exploit dispatch are unchanged. Source SHA256 is
`7f514b48e5685518b6bb2740abfbf64e0ea2015601a276f6750b76ac9d671e6a`.

Identical final source/spec/capture inputs reproduce **45/24** then **45/0**,
with 38 owner examples plus 7 eager support examples. The parent's combined owner and
readiness suite passes **49/0**. Actual-capture fixtures, original RESP parser,
real auth helper, TCP close/unregister, repeated checks, operation-specific errors,
cleanup failures and unexpected faults/interrupts are covered.

## Separate harness findings

An earlier authenticated frame is retained at 9/3/0. Its native Bash session works,
but msfconsole remembers the generic payload from the preceding command example.
That attempt does not qualify default owner sessions. Running the default case
before payload overrides preserves the default criterion and yields two used
owner sessions on one selection. This is separate from the two real defects.

Review also catches the readiness flag being set before resource/preservation
checks. Four focused guard examples require all guards to pass and withdraw a
previous success after failed requalification: corrected identical units go
**11/3 to 11/0** including 7 support examples. The initial unit fixture omitted its
runtime stub and fails 11/4; that setup fault is retained separately. The functional
original frames had already passed their real native/resource/preservation gates.
The new gate ordering strengthens failure withholding; diagnostic proof capture
also moves before UI assertions. Thus native before/after harness bytes are not
claimed identical. The production source-only unit comparison remains identical.
An unset runtime environment also permits ordinary spec discovery without an
outside-example error. No protocol/session/payload response stubs enter native
profiles. A final README result/status update is a separately recorded
**documentation-only input refresh** after execution; runtime input bytes match.

## Retained evidence and limits

Private evidence is under `tmp/redis-lua-feasibility/`. Original wrappers are
`tmp/invoiceshelf-feasibility/functional-20261121T195450` and
`functional-20261121T195902`; the repaired wrapper is
`functional-20261121T201140`, whose runtime is
`tmp/module-target-tests/20261121T201142-44737d/`.
`QUALIFICATION.json`, source-fix evidence, readiness units, actual profile logs,
input snapshots, passive method/wire events and native journals retain every
attempt. These local raw artifacts are not added to the repository.

Thirteen additional ordinary sessions are fully used/closed across retained
frames, including eight owning calls. The passing set reaches **162 cases /
41 profiles / 457 current inputs**, with 86 retained ordinary and 21 separate
candidate-source sessions. All 28 new cgroup captures show zero OOM/PID events.
All 18 new / 781 recorded Docker resources are absent, including two unused automatic
agent-startup tool helpers removed promptly after global inventory. Profiles use
one capped target; the brief observed global peak including those helpers is 3.
Both contexts contain no running or stopped containers, all callback ports 4492-4495
are closed and no local msfconsole/guard process remains. No image/cache prune or
daemon change occurs.

Six changed Ruby files have **zero new offenses**. The source retains two
`Lint/ModuleDefaultPayload` offenses; source msftidy exits 2 for these inherited
defaults. Module documentation tidy passes 0 and all 5,923 human Scenario bytes stay
unchanged. Full-suite/CI success is not claimed from local targeted checks.

Linux dropper and its missing stock-image wget prerequisite, other payloads,
TLS/ACL users, non-ASCII AUTH through the unchanged Redis mixin, other releases
and architectures, systemd MemoryDenyWriteExecute and database reporting remain
unqualified. Existing Safe results for missing Lua libraries/nil command replies
are retained behavior, not proof that every such service is unaffected. Earlier
ProjectSend failures and every other valuable feasible module remain in scope.
No PR or external comments are created.
