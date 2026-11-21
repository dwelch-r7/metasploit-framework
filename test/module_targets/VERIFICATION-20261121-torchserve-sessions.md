# TorchServe session readiness investigation

The default Java session path remains **unqualified**. Two actual owner attempts
produce no session after working standalone controls. A stronger native MAR
control also produces no session inside the genuine TorchServe JVM; the final
gate correctly withholds the owner. The cause is unresolved. These observations
do not establish a module-specific HTTP delivery defect, and no production code
is changed to obtain a pass.

The [strict diagnostic](torchserve_sessions/README.md) retains its source,
pinned recipe, expected four cases and `manifest.deferred.yml`. It is excluded
from automatic registration. Its README gives an explicit temporary-manifest
reproduction command. The earlier [native/check qualification](VERIFICATION-20261121-torchserve-checks.md)
remains valid: all 188 declared inputs are unchanged. Campaign totals remain
**322 runtime owners, 686 qualified profiles and 4,828 historical cases**;
the latest qualified set still has sixteen stated profiles, 53 cases and
twenty-two used/closed sessions. Failed frames add no qualification.

## Independent controls before attribution

The target is unchanged official TorchServe **0.8.1**, Linux amd64, UID **1000**
(`model-server`) and JDK **17.0.7**. The application image and JAR fingerprints
come from the [existing recipe](torchserve_check/vendor.json). Genuine native
constructor, installed YAML-reader, MAR download/list/delete and physical-proof
controls pass before each session frame. No vendor parser or protocol handler
is replaced. A native callback proves the route, PID birth and owning socket.

The first stock control directly launches a real generated Java JAR under the
existing `multi/handler`. The second extracts that JAR's unmodified class and
configuration, serves them through Python's standard HTTP server and invokes
the payload with an ordinary JDK URLClassLoader. Its supplied Java source is a
reflective launcher, not a replacement payload or handler.

Both stock controls retain the normal **Spawn=2** setting. Every admitted
session writes exact physical proof bytes as UID1000, returns `model-server`
identity, matches an original SQL session row, and owns the sole established
callback socket by PID/birth/inode. Public shutdown follows a fresh response;
the payload processes and active sockets disappear, original rows gain
`closed_at`, and the full application process set returns to baseline.

The owner uses the observed default target 0 and
`java/meterpreter/reverse_tcp`, also Spawn=2. Its actual MAR bytes match the
physical downloaded archive. Passive traces show its actual class and
configuration responses match the working stock control. The payload class is
8,765 bytes, SHA256
`f2d768ccb588b5bb61d18769b04c2adcc92ec17ca00032808a1aad8235820c0b`.
These are real producer/physical reads, not assumed output.

The stronger third control independently builds and registers a native MAR.
It uses the repository's existing `MyScriptEngineFactory.class`, the same stock
payload/configuration and a standard HTTP source. This exercises the genuine
application JVM context without the module's MAR or HTTP producer. Registration
returns ClassCastException/HTTP500 and leaves the exact MAR, but no session
arrives. HTTP500 alone is not an execution proof, as established by the earlier
harmless constructor controls. The owner is withheld after this failed gate.

## Retained frames

| Frame | Examples / failures / pending | Stock sessions used/closed | Outcome |
| --- | --- | --- | --- |
| `20261121T073629` | 2/1/0 | 1 | JAR passes; default owner has no callback |
| `20261121T074425` | 3/1/0 | 2 | JAR and ordinary HTTP loading pass; owner still has no callback |
| `20261121T074932` | 4/1/1 | 2 | Both stock controls pass; native MAR has no callback; owner withheld |

All **five stock sessions** are genuinely used and closed. All three complete
frames remain failed. No owner session, same-selection owner repeat, embedded
Java (`Spawn=0`), Java shell, other release or deployment is qualified.

Both actual owner attempts return HTTP500 from registration and HTTP404 from
their original DELETE cleanup. The physical MAR remains afterward; its bytes
are retained before exact fixture removal. The native MAR also remains before
fixture recovery. Neither operation establishes automatic module artifact
cleanup. The initial naming lint offense is corrected separately; it does not
explain the no-callback behavior.

## Checks, cleanup and evidence

Four new Ruby files pass RuboCop, excluded spec discovery passes without Docker
configuration, and the Compose configuration validates. Runtime code in the
retained final frame matches the maintained diagnostic. Its manifest is only
renamed to defer registration; documentation adds the observed outcome. No
production source or human module Scenarios change.

Stacks run serially with at most **two capped containers**: the application at
1 CPU/1536 MiB/equal swap/256 PIDs and disposable PostgreSQL at
0.2 CPU/128 MiB/equal swap/64 PIDs. Ports are published on loopback. All 24
memory/PID event captures are zero; this does not prove CPU/JVM-context readiness.
Native HTTP sources are terminated and reaped in ensure blocks. No subagent or
tool-helper container starts in this tranche.

All **six new containers and three networks** are independently absent. All
**449 recorded Docker objects** are absent, the global inventory has **zero
containers including stopped ones**, and no owned ephemeral network or volume
remains.

Three immutable raw-frame capsules retain inputs, complete console/native
records, original SQL rows, physical proof/archive bytes, process/socket state
and cleanup IDs. Their manifest hashes are recorded in the aggregate evidence
capsule under `/Users/dwelch/.codex/reports/`. Publication binds the committed
diagnostic and reports separately. No PR is created; the broader goal is active.

## Self-review and next discriminator

**Summary:** The investigation separates working stock payloads from failed
native application-context readiness, rather than inventing a module fix.

**What looks good:** Exact bytes, original reporting IDs, public remote shutdown,
full process/socket reset and a stronger failed native gate limit the verdict.

**Concerns:** The initiating application-context cause, default owner sessions,
repeat behavior and module artifact cleanup remain unresolved.

**Suggestions:** Compare the genuine JVM's properties/environment and physical
spawned class/config/process behavior with the working CLI controls. Test any
resource change as a controlled variable. Preserve the failure when testing
other payload settings; a working Spawn=0 path would not repair Spawn=2.
Continue the broader valuable-module inventory alongside this deferred issue.
