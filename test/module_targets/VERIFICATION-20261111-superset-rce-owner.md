# Superset RCE owner investigation — 2026-11-11

The confirmed binary-restoration defect is repaired and verified against genuine
native state. **RCE remains unqualified.** The checkpoint stays at **186 runtime
modules, 128 qualified profiles and 1,447 functional examples**. The repaired
source also passes all four 2.0.1 check/gather examples; no RCE session example
is added to those totals. Static inventory has 188 registered sources, fifteen
individual reviews with none stale, and 316 pending documented container hints.
Registration does not establish qualification.

Run the [owner investigation](superset_rce_owner/README.md):

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb superset_rce_owner superset_cookie_201
```

Each profile uses four containers capped at 2,144 MiB and 2.15 CPUs, running
serially under one shared lock through capture and teardown. Only the gateway
publishes a random loopback port. The [native preparation](VERIFICATION-20261111-superset-rce-native.md)
provides the genuine pinned target and independently verified SQL/permalink
prerequisites. No application handlers or Framework responses are substituted.

## Actual baseline and repair replay

| Run | Owner source | Actual result | Interpretation |
| --- | --- | --- | --- |
| `a8861c` | Unchanged owner; worker `14d6d452290` | Five examples, four failures; 215.254103 seconds; natural exit1 | Check passed; owning Meterpreter executed commands, shutdown failed, original permalink bytes corrupted; later state guards blocked cases |
| `575b4d` RCE | Repaired owner; worker `144ffe47d2c` | Five examples, five failures; 216.493954 seconds | Owning shell executed commands and closed cleanly; original bytes restored; draft SQL assumptions and a residual row blocked completion |
| `575b4d` 2.0.1 | Same repaired source | Four examples, zero failures; 87.197526 seconds | Current check/default AutoCheck gather/forced repeat path passed |

All have zero pending or outside-example errors and passed physical cleanup.
The combined repair invocation naturally exited one because RCE remains failed.
Different case ordering and payloads explain why failure counts alone are not a
before/after verdict. They are not five independent owner defects.

Both RCE invocations first passed native cookie controls, real PostgreSQL
login/query, and two complete native SQL/permalink/deserialization cycles.
Two independently generated Python payloads then ran directly in the real
application with actual handlers: Meterpreter session1 and command-shell
session2 each performed a filesystem operation as UID1000, matched native
socket ownership, and released their target sockets and Framework sessions.
This establishes the selected transport setup before owning calls.

The unchanged owner opened Meterpreter session3. It returned PID1185 and
created its proof as UID1000. Shutdown failed the target-socket-release gate;
observations retain both Gunicorn PIDs113 and1185 owning the same inode,
transitioning from established to `CLOSE_WAIT`. The cause remains unresolved.
Its SQL cleanup corrupted the two original permalink BLOBs by saving the
literal backslash escapes from Python's bytes representation as new bytes.
An additional newly created permalink row also remained.

With the repair, the owning Python shell session3 returned PID114, performed its
filesystem operation as UID1000, released its socket and left no active
Framework session according to the recorded lifecycle. All three original key
rows match exactly afterward: both existing permalink BLOBs and the native
application salt. Other selected account/datasource/dashboard state and SQL
tabs/table schemas match baseline. Row4, a newly created permalink row, remains.
That residual row stops the strict pristine-state guard. Its intended artifact
contract needs investigation; this report does not assume that every residual
row or every failed assertion is an owner defect. Repeat runs and later owning
Meterpreter/negative paths were not reached after that guard failed. Fresh
canary HTTP requests after the owner were also blocked by that guard.

A read-only SQL capture independently proves two real nonreplayable account
hashes and their connected origin/service/workspace graph. Decoding their
reported cracking format reproduces the exact native account representations.
It also shows lowercase `apache superset` service names and one login per core.
The draft incorrectly expected CamelCase and no login; those assertions have
been corrected. A follow-up query missed project teardown, so the login status
and attempt timestamp were not observed in that capture. The corrected future
assertions must verify `Untried` and no attempted-authentication timestamp.
These fields and repeated credential persistence are not claimed as passed.

## Focused repair and source checks

The owner now selects `hex(value)` and SQLite storage type before implantation.
CSV therefore carries exact bytes without parsing Python bytes literals.
Cleanup validates complete saved rows, restores BLOBs through SQL hex and text
through a typed cast, preserves saved values across calls, and continues API
cleanup when an individual restore is refused or receives no response.

Eleven isolated whole-owner examples pass in the primary worktree (0.094470
seconds). They use actual native CSV/BLOB captures and a real in-memory SQLite
receiver, with explicit HTTP/UI/payload boundaries and blocked unexpected
process/network execution. They cover exact restoration, unrelated salt,
repeated cleanup, binary/text compatibility, invalid metadata and refusals.
They do not establish native owner sessions by themselves. Only `rce_implant`
and `cleanup` changed; ten other owner methods remain identical.

An independent producer review caught an additional test assumption: Ruby's
CSV writer quoted empty strings, while the Superset exporter can leave the
middle hex field unquoted. The two new empty BLOB/TEXT cases failed before the
follow-up and pass afterward. Producer execution used bundled local pandas
2.2.3 with the unmodified official Superset CSV helper; historical pandas1.3.4
writer behavior was source-verified. These are compatibility inputs, not native
empty-permalink captures. Missing columns and unsupported storage types remain
rejected. No dependency was added; SQLite is already a Framework dependency.

The failed RCE runtime selected 72 inputs; its exact owner source matches the
committed repair. Two draft test/document files were corrected after capture:
the SQL expectations and investigation README. No subsequent owner replay is
claimed. The passing 2.0.1 result has all 66 selected inputs current in the
primary worktree. Original raw result maps, paths and revisions remain unchanged.

## Evidence and cleanup

Root observed each actual first console prompt, isolated returned BOOT and two
fresh parsed atomic metadata snapshots: 7,264 module entries and two cache
entries, with no first-profile seed. The second profile used the ordinary
within-invocation cache path. All four source/cache/seed/config copies match
byte-for-byte; preserved source timestamps are expected. No metadata was
manually seeded. Root live inspection verified the exact four roles, resource
limits and no OOM kills for both repair profiles.

Root teardown passed 23 independent queries: exact absence of eight container
IDs, four network IDs and four owned volumes, absence of both projects' resource
labels, and an empty global container inventory. Images and unrelated volumes
remain. All 160 original repair-run files imported byte-for-byte. The 254-file
seal manifest is `04b3f0ef30eabf5a5c526784efafeb9458e5fcd283292431ed187304bcdc621e`.
The original 176-file runtime failure seal is
`a2ce141b96ff7d763db064c0aadf0f5bc58f6eca7e1efe6379261de78a26829a`.
Source/producer seals remain separately verified:
`8226edce3c05565f5ce410937c844fcc04142eedf73387c112d92fc4ab169719`
and `2a574ca48f75fac28bcb73cf592a2b99030689e90c92d27619ab9aa3186bf3a7`.

Earlier attempts remain setup evidence: `980bdc` was deliberately interrupted
before native/owner examples to fix cached module options; `82b46a` failed
calibration-file removal permissions; `beff0f` stopped at required listener
options and a reused artifact counter. Their exact root teardown passed twelve
queries each. They are not owner exploit failures.

Five changed Ruby files pass syntax checks; Python/JSON syntax checks pass.
Non-owner Ruby lint is clean. The owner retains exactly fourteen baseline lint
diagnostics; module tidy exits2 for those same diagnostics. The changed module
document passes its checker, and human Scenarios remain byte-identical. The
five-case discovery check was dry-run only. No full suite was run.

**Summary:** Native replay confirms the binary repair and current 2.0.1 profile.
The owner investigation remains excluded from qualified totals.

**What looks good:** Actual sessions performed operations, independent native
controls passed, SQL graphs and exact original bytes were captured, and all
physical resources were independently removed.

**Concerns:** Meterpreter shutdown, the residual permalink contract, repeat runs,
remaining negative cases and the corrected SQL status assertions need further
qualification. Fixed/rotated-key releases and other platforms remain separate.

**Suggestions:** Investigate those retained failures before another RCE replay;
continue the remaining valuable Docker-feasible module queue. Focused checks do
not establish full-suite or exact-head CI success. No PR was created.
