# SIP and integrated checkpoint, November 10

Current hashes, exact passing counts and owned teardown establish **161 runtime
modules, 89 families and 1,177 functional cases**. Seven SIP/Manager modules add
42 cases to the [NiFi processor checkpoint](VERIFICATION-20261110-nifi-processor.md).
The campaign remains incomplete; other endpoint requirements and retained failures
remain individually recorded rather than classified from a failing test alone.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb sip sip_enumeration sip_capture asterisk_login
```

Pinned genuine Asterisk18.10.0, sipsak0.9.8.1 and SIPp3.6.1 provide UDP/TCP/TLS,
registration, protected accounts and Manager controls. Native real clients,
AsteriskCLI/Manager state and an unrelated BIND service precede module execution.
A disposable database proves service/note/credential reporting. There are 84
actual public module runs, including the expected capture bind refusal.

| Profile | Cases/failures | Current inputs | Native CLI operations | Native seconds |
| --- | ---: | ---: | ---: | ---: |
| sip |18/0|69|43|11.715|
| sip_enumeration |14/0|75|112|35.214|
| sip_capture |7/0|75|57|20.342|
| asterisk_login |3/0|70|40|15.332|

Final invocation `20261110T075425-147c5c` terminates naturally with zero pending
or outside errors and successful preflights/recorders/teardowns. Its union has94
current files, frozen during the complete run. First actual prompt, returned
isolated BOOT and fresh parsed metadata snapshots remain in original receipts.

## Repairs and attribution

Four focused repairs correct genuine source defects: enumeration padding and TCP
response parsing; deregistration retaining Scanner targets/default5060; capture
listener startup/bind cleanup; complete Digest credential/hash reporting. TCP
parsing reuses the existing unchanged SIP response parser. Capture records actual
UDP peers and UNTRIED nonreplayable hashes, using one formatter for database and
optional John files. Malformed or unsupported input is challenged without
inventing a credential. No shared SIP/NAT/TLS/runner/dependency/timeout change.

The complete original corpus first passes24/42, then25/42 after correcting fixture
TLS enumeration ports, actual job/schema contracts and explicit legacy policy.
Startup-only capture still fails5/7 on real reporting data. A pinned native John
build then rejects both the old source and the initial test oracle:13 separators
are invalid. Correct14-separator records using the signed Authorization URI
recover4/4; the request-URI counterfactual recovers2/4 and leaves SIPp's two hashes.
The exact upstream qop vector recovers its password. These controls precede the
reporting repair. Final emitted files recover8/8 records, two unique hashes,
zero left; the earlier strict capture run separately recovers12/12 and is not
added to the42-case total. Database status remains UNTRIED.

Earlier setup failures from internal-bridge publication, a missing wait context
and an invented SQL column remain setup/observer failures, with original bytes.
Matched focused17/8→17/0 changes only four owning sources across19 inputs;
corrected John18/18→18/0 changes only capture source across11 inputs. No simulated
protocol, fabricated console scenario or successful banner substitutes for proof.

## Parent verification and evidence

Parent independently checks all3,333 immutable worker checksum entries, all94
current source hashes and all281 imported invocation files byte-for-byte:
`/Users/dwelch/.codex/reports/sip-module-validation-20261110-6469343e74c2`.
SHA256SUMS SHA-256 is
`6163816774fab63d4a2f7ea1a7a497c81aa344092355e05cce337d04e7bb47ce`.
Actual commands, failures, source/fixture copies, PCAPs, proof files, John output,
console receipts and native status observations remain available there.

Parent focused41 examples pass, selected dry discovery finds42, and ten new
Ruby/support files lint clean. Four owning sources reduce65 inherited lint
findings to42 with zero new findings; all four msftidy checks exit0. Actual module
docs retain the same missing Options INFO and three backtick warnings, with
human Scenarios and all original prose unchanged except the exact added guide
section. The initial temporary docs comparison lacks a mirrored module path and
adds an observer-only ERROR; corrected mirrored layout and actual path both
retain only the inherited diagnostics. No full local RSpec suite was run.

All295 parent resource checks pass:38 exact owned projects,180 recorded anonymous
volumes and the John component label have no remaining resources. Build images
remain caches. Parent receipts have a separate immutable checksum manifest;
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-800e4d590d5`, 50 entries, manifest SHA-256
`d3c22114ce00ce6532d55e334f5bc96607cec84922ce97054f1da164aeebe6c9`.

## Explicit limits

A401 challenge is a candidate, not validated account existence. Deregistration
uses a separate real permissive node with `pedantic=no`; strict native refusal
from a missing From tag and default Via return routing remain explicit. Repeats
restore real registration state; historical Reg-Contact is not live registration.

Native ordinary OpenSSL rejects an untrusted certificate and explicit fixture
trust accepts it. Installed Rex0.1.71 PEER also accepts it because its callback
returns true. Peer-verified flags do not qualify trust enforcement; this is an
inherited observation with exact native/source evidence, no TLS source change.

Live qop negotiation, other algorithms, IPv6, proxies/media/calls and ManagerTLS
remain unqualified. Seven other SIP-related modules retain source-hashed
individual requirements for genuine devices/OS/endpoints or additional APIs.
