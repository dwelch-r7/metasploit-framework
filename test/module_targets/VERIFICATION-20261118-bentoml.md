# BentoML sessions and Python stager recovery, 2026-11-18

Qualified three BentoML profiles for two new owners, plus the previously
unqualified pgAdmin staged/inline regression: **44/0 across four profiles**, with
24 genuine sessions, zero pending/outside errors and successful teardown. This
reaches **295 runtime owners in covered paths, 598 qualified profiles and 4,186
historical functional cases**. Both BentoML module sources are unchanged. The
repair is in the shared Python TCP stager. The broader campaign remains active;
no PR is created.

## Reproduction and native prerequisites

The [BentoML guide](bentoml/README.md), linked from both module documents, keeps
Compose profiles, hash locks, fixture source and automated tests together:

```sh
python3 test/module_targets/bentoml/prepare.py
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb bentoml bentoml_runner bentoml_fixed pgadmin_session_meterpreter
```

The genuine API and legacy runner use BentoML 1.4.2; the patched API uses 1.4.8.
A tiny batchable Echo service and NumPy absolute-value model exercise actual
vendor routing and serialization. Python 3.12.12 linux/amd64 is digest-pinned;
complete requirements lock 73 distributions, differing only in BentoML's version.
Official wheel checksums verify installed vendor Python sources before and after
owning calls. Native controls prove ordinary predictions, valid pickle execution,
negative content-type/path behavior, UID1000 and exact canary recovery. The patched
API returns 415 without execution while ordinary predictions pass. Host controls
never unpickle target data. Native application success precedes loading the owner.

The API advisory identifies 1.4.3 as fixed; the selected patched runtime is 1.4.8.
BentoML 1.4.8 removes the public `start-runner-server` CLI and its implementation.
That process exits 2; an unavailable standalone runner supplies no runtime-safe
comparison. The sources and original failed startup are preserved.

Each fresh project has one work container, one CPU, 512 MiB memory/equal swap,
PID128, init and a random loopback HTTP port. BentoML runs as UID1000 without
privileged mode or host mounts. The stock pgAdmin 8.3 regression uses its existing
pinned image, UID5050 and disposable data volume. Framework uses host Ruby 3.3.13;
native controls use the existing host Python 3.14.6 and target interpreters.

## Qualified functional results

| Profile | Cases | Real sessions | RSpec seconds |
| --- | ---: | ---: | ---: |
| `bentoml` | 16/0 | 10 | 164.0 |
| `bentoml_runner` | 14/0 | 10 | 154.0 |
| `bentoml_fixed` | 5/0 | 0 | 33.3 |
| `pgadmin_session_meterpreter` | 9/0 | 4 | 100.1 |

Both vulnerable owners cover checks, handler-free Python and Linux commands,
staged/inline Python Meterpreter, Python command shells, Bash and Linux HTTP-fetch
Meterpreter. Every family repeats with AutoCheck disabled and the same console
configuration. The API covers explicit/unrelated endpoints; both owners check an
independently unused port. Runner detection is passive Detected, with actual RCE
proved separately. The patched API covers Safe, real AutoCheck refusal and forced
nonexecution for both targets.

Each session registers through Framework and its ready event, performs a real file
operation and proves exact native bytes/UID. Meterpreter channels return to their
prior set. Kernel TCP state and BentoML descriptor ownership are captured around
public shutdown. Selected proof/fetch/upload files are recovered, local sessions/
jobs finish empty, and repeated execution works. Fork-child zombies can persist
until container teardown; process-table equivalence is outside the recovery scope.

All **64 resource-event files are zero**. All **nine individual containers,
networks and the pgAdmin volume** are independently confirmed removed, and both
Docker contexts finish empty. All **88 declared input files** match their captured
SHA256 values before sealing. Unrelated auto-started AWS/GitHub MCP containers are
removed by task-local housekeeping; global settings, images and unrelated volumes
are preserved. The full campaign continues to use one heavy pipeline at a time.

## Confirmed failure and repair

The original API cohort records 16 cases with two staged shutdown failures;
the runner records 14 with the same two failures. All 20 sessions perform real file/
API operations, and native before/after predictions and resource gates pass.
These failures therefore do not establish an invalid vulnerable application.

A focused ten-case comparison maps the actual socket inode to both the BentoML
service worker and its forked Meterpreter child. After public shutdown, the child
is a zombie while the service parent still holds the descriptor in CLOSE_WAIT.
Inline payloads connect after forking and show only the child owning the socket.
Some zombie fd directories deny inspection; positive parent ownership and the
independent kernel TCP state remain captured.

The TCP stager connects before executing the downloaded Meterpreter stage, whose
fork leaves the parent with a duplicate. A `try/finally` now closes this process's
socket when stage execution returns or raises. It uses `close()`, preserving the
child's independent descriptor. No shared worker PID is signalled or garbage
collection injected, and closure assertions remain strict.

Changing only `lib/msf/core/payload/python/reverse_tcp.rb` among 65 declared inputs
makes the focused comparison improve **10/2 to 10/0**. Both replay images have
identical filesystem layers. The repaired sessions show only the child owning
their live socket; all four connections disappear after shutdown. The final
aggregate also makes the earlier pgAdmin 9/2 diagnostic pass **9/0**. The temporary
focused profile is sealed with its inputs and removed; its cases are excluded
from the 44-case breadth increment.

Four behavioral contracts execute generated Python over real local TCP with the
embedding interpreter and namespace retained. They cover normal return, the retry
branch, propagated stage errors and actual forked child traffic. Original code
fails all four socket expectations; repaired code plus 13 adjacent Python examples
passes **17/0**. An earlier missing `rex/text` test import causes NameError and is
preserved as a harness error, with no regression claim. Ruby syntax, Python AST,
new Ruby lint and both module-document tidy checks pass. The library retains 15
unchanged RuboCop offenses; no new offenses are introduced.

## Preserved setup failures and remaining limits

The first native runner client reads request `Payload-Meta` instead of response
`Bento-Payload-Meta`, causing a decoder failure after a real successful response.
A later malformed negative protocol request times out; it has no established
rejection contract. Both occur without loading an owner. Corrected native controls
use the real response header and an unrelated-method 404 negative, preserving the
failed cohorts separately. Guarded refusals caused by reappearing MCP containers
produce no module verdict; the patched API subsequently passes 5/0 independently.

The API owner's unrelated ENDPOINT request receives 404 and does not execute, but
the owner does not classify that response as an exploit failure. Other releases,
architectures, TLS/proxies and transport-loss behavior remain unqualified. The
separate SSL stager has its own generator; this TCP repair supplies no SSL runtime
claim. Human module Scenarios remain unchanged.

Prior checkpoint 6fd3d8 CI has nine successful workflows. Its Meterpreter report
job is queued at this observation; actual 6fd3d8 checkouts are verified for two
failed native Mettle workers: macOS 46/1 (double-quoted echo assertion) and Linux
51/3 (HTTPS minimal-URI profile receive bounds in meterpreter/unix/search tests).
Their causes remain unverified. Verify's actual Ruby 3.4 checkouts pass 20,505/0
with 33 pending and 6,781/0. Those older runs do not test this new stager repair.
No workflow is rerun or cancelled; publication CI is tracked separately.

## Evidence and remaining queue

| Capsule | Immutable directory basename | SHA256 of manifest |
| --- | --- | --- |
| Native protocol calibration | `bentoml-native-prototype-20261118t105218` | `83b1fdd34efe4baf8a132de655f40fc3de95fce7f0bd0c9ed7763520a09c0d86` |
| Locked native controls | `bentoml-locked-native-20261118T113346` | `74c1a24bfac587c364cecccfe0cb44857fdee3afc866f19e9b0701432c69f093` |
| Original API | `bentoml-first-api-20261118T113404-701c30` | `38734f1644dad2b7a091c7d1d08d4bd0f7892d9b8b176d7161c8a535f86539cd` |
| Original runner and guarded refusal | `bentoml-first-runner-fixed-20261118T113800-e71fda` | `286dd3550ae85810d52bc3d215f1147a520b77aeb435c4320d0fdc8f6d858610` |
| Descriptor baseline | `bentoml-socket-baseline-20261118T114713-f5762e` | `28493f08af83772981be4b9789963f0a2da5eab368995962e8d174726b7476f2` |
| Stager-only replay | `bentoml-socket-replay-20261118T115422-18a43a` | `113fa66611d6e073476da188da276c8f196f6016171ae0f710ef0e5c56615a77` |
| Generated-Python contracts | `python-stager-contracts-20261118T115358` | `db187c9812f5f30e5fe2cc292e16984aa5429b8ec1b64dda0d4a4e1712097d3d` |
| Final qualification | `bentoml-qualified-20261118T120012-af3a15` | `2394d7a35337282f309f8e80861b5825290aec2b225dbd7af36ad6d19334d1b1` |

Final capsule: **411 files**, run `20261118T120012-af3a15`. Source-only replay and
scope auditors, original failures, exact input snapshots and native replies are
preserved. The current static inventory contains **5,179 source
files, 4,300 pending selectable candidates,
225 pending documentation hints and
0 stale source reviews**. Registration alone supplies no
functional pass. The broad goal remains active.
