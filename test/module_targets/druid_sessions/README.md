# Native Druid session delivery diagnostic

Run `bundle exec ruby tools/dev/run_module_target_tests.rb druid_sessions`.
The five cases each require two executions through the unchanged real module:
JavaScript netcat, authenticated wget x64 Meterpreter, wget x86 shell, JNDI Bash,
and prefixed JNDI netcat. See the
[shared target guide](../druid/README.md) for pinned releases and topology.

Native setup independently samples genuine rows, proves both vulnerability
boundaries, compiles the [harmless ELF source](native_exit.asm) with the NASM
already installed in the canonical Framework image, downloads exact bytes with
real wget and requires actual target exit status 42 for BOTH x86/x64. The native
prerequisite run also proves Bash TCP redirection, netcat HTTP and FIFO creation
as UID/GID 1000. No new project dependency or opaque binary is committed.

Sessions must produce Framework's post-bootstrap open event and then execute a
real remote command. Fresh target bytes/UID, the actual remote PID live in the
container and its subsequent disappearance are independent gates. Graceful
remote shutdown precedes host kill fallback. An exclusive target process
inventory, TCP/UDP listener state, HTTP service ownership/resource probes and
exact file restoration permit a second execution on the SAME ports. Forced
operator process cleanup is retained as diagnostic evidence and cannot repair a
failed graceful-exit assertion. A broken console stops later labels.

Actual target-namespace PCAPs retain HTTP, LDAP and callback traffic. Complete
ELF HTTP response bytes are saved and labelled as actual wire responses; they
are not described as recovered target files. A public compatible-payload catalog check precedes every real run. The JNDI
Linux-labelled target declares Unix and rejects Linux fetch payloads; this
profile does not bypass that restriction. Readiness requires a post-bootstrap
event within an explicit 30-second wall-clock bound. Packet capture uses a
16 MiB kernel buffer and requires zero kernel drops after an earlier
capture dropped 316 packets. The current last-owner HTTP service
contract requires a closed listener and a real refused URL probe, plus no
service-manager owner. A persistent pooled listener must be investigated with
its actual resource/refcount state rather than silently called closed.

Sampling remains at least once; no exactly-once or single-session promise is
inferred. Default Python/curl, Linux fetch on JNDI's Unix target, Windows, other
JVMs, HTTPS and other architectures are not qualified by these five cases.

The first original run was 5/3: JNDI Bash did not reach the fixture's short
ready wait; JS Meterpreter passed both remote proofs before capture loss; the
unsupported JNDI fetch payload was rejected before HTTP. All original bytes,
failures and 86 input hashes are preserved. This corrected original corpus
then completed 5/2 with eight opened, eight used and eight gracefully removed
remote PIDs, zero packet drops and four actual ELF HTTP responses. Both JNDI
failures were the module's reported HTTP error after successful execution.
Qualification of repaired sources still requires all five cases and both
iterations, unchanged current inputs and a clean terminal resource audit.
Human-written module Scenarios remain unchanged.
