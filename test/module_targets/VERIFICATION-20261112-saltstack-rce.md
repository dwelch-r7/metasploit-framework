# Salt master/minion session verification — 12 November 2026

The [session lab](saltstack_rce/README.md) qualifies the defined Salt 3000.1
Linux session and job-completion contract. The checkpoint is **211 qualified
modules, 193 profiles and 2,056 functional examples**. Registration of 213
sources is not qualification; 290 documented container hints and unhinted
candidates remain. No pull request is created.

## Final complete result

Run `20261112T091804-f12cfc`, source
`2b332cf445960f758bbeb302cbe44af08e76614c`, passes **nine examples/zero failures**
in 455.43 RSpec seconds, with no pending examples or outside errors. The original
manager and independent observer exit zero. The first cold prompt, BOOT record
and both fresh metadata snapshots are independently observed. All eight exact
cleanup queries pass; all three containers and their network are removed, and
Docker is empty.

Fourteen owning calls cover check repeats, all four targets twice, selective
minion execution, wrong credentials, a missing selector and a refused port.
There are **eleven owning session proofs**, independently linked to actual SQL
IDs, plus one genuine native SDK SSL control. Minion Python is the first
Meterpreter use: Stdapi is confirmed unloaded, then both minions complete real
RPC/file/process proofs twice. Unix minions execute on both nodes, then only the
selected node. No owning payload, vendor method or transport response is replaced.

Five passive owning observations, including the no-match case, verify seven
actual minion workers: real proc bytes, JIDs, configured cache paths and witnessed
session ancestry. Cache envelopes report success with retcode zero, proc paths
disappear, and role logs contain no job exceptions. All seven owning workers
have been reaped by the final snapshot, so their exact exit statuses are
explicitly unavailable. Native before/after calibration captures thirteen
workers terminal with raw wait status zero; one native worker is already reaped,
also with its exit status unavailable.
The final target log contains **zero `KeyError: 'ret'` occurrences**.

Native preflight and final audit each pass all five publication cases and verify
the actual `jobs.py` JID/node envelopes. Thirteen vendor files, fifteen runtime
packages, configuration, role/process identities and cgroup event counters remain
consistent. All five owning observers stop, export and rehash their evidence,
then prune only their own UUID directory. Session processes, transports,+listeners and Framework jobs close between repeats.

The final read-only seal contains **1,074 entries / 72 input files**, manifest
`706638202ab73510798c181c143b1054d7a6f95f807699626ae0cb6d2f292375`.
The parent independently rehashes every entry. The helper pilot's separate seal
contains 180 entries, manifest
`15f9935b3b0eb90b14f2541916c246359db551752f697ca5073dfd58c1f3b4f5`.

Reproduce with:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb saltstack_rce_3000_1
```

These results do not qualify other Salt releases, separate hosts, appliances or
the remaining Salt modules. Actual proc removal is credited to Salt itself;
the module's hardcoded default FileDropper path is not validated with the two
custom cache directories. The earlier failures below remain historical evidence.

## Genuine target and controls

Salt 3000.1 runs a normal master and two accepted minions from the collection
lab's pinned source-built image. Native controls verify thirteen installed
vendor files, fifteen runtime packages, configuration and daemon identities.
Authenticated commands, wrong-root-key rejection and five selective/all/missing
PCRE publications use genuine Salt APIs and actual file markers. Distinct
daemon environment tokens distinguish execution roles on their shared host.

The full profile uses three serial containers capped at 1,408 MiB and 1.7 CPUs.
No application source or transport response is replaced. Real session APIs,
target process/file checks and actual PostgreSQL queries supply the assertions.
The independent SDK control uses legitimate authenticated execution and cannot
establish unauthenticated exploitation.

## Verified module defect

Both minion targets originally serialize normalized `MINIONS` directly.
Framework's actual `OptRegexp` produces a Ruby `Regexp`, which MessagePack
rejects with `undefined method 'to_msgpack' for an instance of Regexp`.
Native publications with the corresponding pattern strings succeed.

The owning fix converts the value to pattern text while preserving the
datastore object and source. Explicit Ruby options map to Python `i/s/x`;
Ruby dot-all `m` maps to Python `s`. This does not translate regex dialects.
The master paths, generic serializer and cleanup registration remain unchanged.
The corrected owning module SHA256 is
`3d3455d8d0e4a8d0ea1ca7a958f60f9537820e64293b1fa0564341db5c4bac30`.

Identical focused specs, seed 53967 and all 21 example identities/order produce
**21 examples/18 exact serialization failures before, 21/zero after**. Socket,
payload data, output and cleanup are explicit doubles; the module, option
normalization, target selection, sender and serializer remain real. The primary
worktree also passes 21/zero. Strict RuboCop and MSFtidy retain the same four
pre-existing default-payload findings; no new spec findings occur.

## Setup and harness defects

The first eight-case run fails before any owning call because its polling shared
context was missing. The next run incorrectly supplies `ExitOnSession`, which
this exploit does not register. These are harness defects, not module failures.

An independent native probe proves the original `/tmp` tmpfs is `noexec`:
direct script execution raises `PermissionError`, errno 13. Salt's Unix master
target executes a downloaded script there; invoking Python directly did not
test that prerequisite. Only the session lab now uses a bounded executable
32 MiB tmpfs. Native executable probes pass before and after the subsequent
functional run. The qualified collection lab remains unchanged.

The SDK control initially polls registered session objects before bootstrap and
database reporting complete, then dereferences a nil database record. Its helper
now waits for the ordinary session-open event and real persisted record before
using proof APIs. The subsequent session-success run below validates it.

## Preserved functional diagnostic

Run `20261112T072221-0c74c0`, source
`c03c5ebb03e8b24fac351fd6331d02b16c936856`, completes **nine examples with two
failures**, no pending examples and no errors outside examples. Native controls
pass before and after. The original manager exits one; its observer exits zero.
The cold prompt, BOOT record and both fresh metadata snapshots are independently
observed. All eight independent cleanup queries pass; Docker is empty afterward.

| Case | Observed result |
| --- | --- |
| Check twice | Pass |
| Master Python, twice | Pass; two actual Meterpreter proofs |
| Master Unix, twice | Pass; two actual SSL shell proofs |
| Minion Unix, both then selected one | Pass; three actual shell proofs |
| Wrong root key | Pass; no session |
| Missing minion selector | Pass; no session |
| Independently refused port | Pass; no session |
| Minion Python, both nodes | Fail; two registered sessions, one fails Stdapi bootstrap |
| Native SDK SSL control | Actual session opens; proof blocked by premature database access |

All seven completed owning session proofs match their real daemon role/token,
root process/file identity and actual SQL session IDs. Each proves remote file
operations and process/transport shutdown before another execution. Thirteen
owning calls and thirteen snapshots of genuine Salt job returns are retained.
The missing second minion readiness event is not treated as successful execution.

Framework logs the cold bootstrap exception
`NameError: uninitialized constant Rex::Post::Meterpreter::Extensions::Stdapi::Stdapi`.
An actual-loader reproduction verifies an interaction between Bootsnap 1.26.1's
require cache and Stdapi's circular import. At the barrier after the real
circular require, Bootsnap's index says loaded while `$LOADED_FEATURES` excludes
the file and the Stdapi class does not exist. Cached concurrent class/class and
module/class lookups fail with the captured NameError; uncached concurrent and
sequential/repeat controls pass. The initial four-case reproduction has two
expected failures, with all probe threads stopped.

The corrected mapper uses a private reentrant standard-library monitor around
the complete existing load and namespace lookup. Dependency versions, load-path
precedence, error text and cache return types remain unchanged. The identical
expanded six-case spec/probe, seed 61823 and example order produce **six/two
before, six/zero after**. The two failures are the cached concurrency cases;
uncached, reentrant, identity and error-release controls pass before and after.
All six fixed child processes exit zero with no live probe threads. Strict lint
retains the same twenty existing mapper findings; both new files are clean.
The primary checkout passes **27/zero** across these six examples and the 21
owning selector examples. The subsequent real cold-session run below passes.

Acceptance deliberately makes concurrent
minion Python sessions the first Meterpreter use and asserts Stdapi is unloaded.
Preloading a single session would conceal this case.

## Evidence and review

### Subsequent session success, outstanding job completion

Run `20261112T075719-f22e0e` at
`11be8b62cb1214a95ddc27521da7fcfcb9bedc9a` completes **nine/zero**, with no
pending examples or outside errors. Its manager and independent observer exit
zero. The cold Stdapi assertion is false, followed by two actual minion
Meterpreter proofs and a successful repeat. All four owning target paths pass
twice: **eleven owning session proofs**, all independently linked to actual SQL
IDs, plus one genuine native SDK SSL session proof. Fourteen owning calls
execute. Native controls pass before and after; all eight independent cleanup
queries pass and Docker is empty.

This run proves the session and loader corrections, but log review finds 42
`KeyError: 'ret'` traceback lines from minion workers after native custom and
owning publications. Their missing return metadata and clean job completion
remain under investigation. Session success alone does not resolve this issue,
so **the profile remained unqualified at that stage**. Its custom minion cache paths also do not
validate the module's hardcoded default proc-file cleanup path. Tested cleanup
covers proof files, session processes/transports, listeners, Framework jobs and
native markers.

Vendor inspection identifies the narrow omitted field as top-level `ret: ''`.
It also shows that `_return_pub` removes the actual proc file and sends the
normal return before optional returner handling reads `data['ret']`. Therefore,
the traceback alone does not establish missing returns or stale proc files.
Native comparison and explicit completion checks are being prepared.

The corrected native comparison, `20261112T082958-1b6c16`, confirms that both
otherwise identical publications execute on both nodes, produce successful
cached returns and remove their actual proc files. Missing `ret` then produces
a returner exception and terminal workers with raw wait status 256 (exit one).
Empty `ret` produces no exception and raw wait status zero. The observed
workers are zombies awaiting reaping, not live workers or already absent PIDs.
The one-container controller exits zero; its six absence checks pass. An earlier
attempt fails ordinary client readiness before any raw publication; that is
preserved as a setup failure. The parent independently repeats twelve absence
queries across both projects, all empty.

The narrow production follow-up adds only `'ret' => ''`. Removing that line
reproduces the prior owning source byte-for-byte. Identical focused specs,
seed 52741 and ordered IDs give **23/three before, 23/zero after**. The primary
checkout passes **29/zero**, including the six loader regressions. The existing
four default-payload lint findings remain unchanged. The module SHA256 is
`19d777dbd7b52933d976dd57f2408e49a9a484f2d86c7a104d2ed7f83190a082`.
At that stage, genuine replay with explicit completion controls remained
outstanding; the final complete run above supplies that evidence.

The independently copied return-metadata unit/native seal contains 146 entries,
manifest `b93eebb5a26ab5df5ff593cd39969125685387e67456d7113d53bbf0d8ad5857`.
The successful native JSON SHA256 is
`d87da2ac4bd473fe91944a9eee8b32ec3f25af42079b4302d9f1734d1728850a`.

The exact-source session-success seal has **460 entries / 71 inputs**, manifest
`949a89af1e556fa24c7d11b3cf420c444bf364e7672b277458d81b174c5330f5`.
The separately copied and independently rehashed loader-unit seal has 139
entries plus manifest,
`9ef53a02eeda37527775efa1c782ff24912f02be54aea7f2ff35045b3abd0e56`.

Raw artifacts remain under `tmp/module-target-tests/<run>/saltstack_rce_3000_1`.
Independent read-only copies retain raw results and exact input bytes:

| Diagnostic | Entries / inputs | SHA256 manifest |
| --- | --- | --- |
| Original polling harness | 178 / 62 | `641f4079787ee6e15382bba2bfd3902f2a0a33f617db279e8dd82a54177f2489` |
| First owning calls | 186 / 62 | `daf2dc552db97d5c80eaca1308f390a2babf8131e027fd32455fd62563c0b9f1` |
| Selector-fixed matrix | 285 / 66 | `b1d27b39aa8f2d7a69857c765ba818ae62a11c077c0c47252d083400fcb1b5c0` |

The separate unit seal has 60 entries plus its JSON manifest,
`08db1eaf4dc385524595b675e7c761da678967c0dbc96993bbd947d9815542cb`.
Every seal is independently rehashed and copied without hard links. Human
module Scenarios remain unchanged.

**Summary:** the selector, cold loader and publication-metadata defects are
corrected; the complete nine-case contract passes. **What looks good:** genuine
native controls, all four target paths, repeated sessions, actual job completion,
SQL identity and exact teardown are independently proved. **Concerns:** owning
worker exit statuses are unavailable after reaping; default FileDropper paths
and other releases/hosts remain outside this profile. **Suggestions:** retain
the failed captures and extend individually to other Salt modules and targets.

CI on the earlier published `9c17653681edcf3e1163907cd1751693d92516d6`
finishes with 62 successful checks, one skipped and one
[macOS Intel Mettle failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43167576037/job/131012941396).
Its network-interface assertions fail; the cause remains unverified. This is
reported separately from the Linux Salt session results and is not attributed
to the unpublished Salt RCE changes.

The later published `880efa4bfb08d5b4c544228b6154630db76ec3bb` finishes with
61 successful checks, one skipped and two Mettle failures:
[macOS Intel](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43181405574/job/131058021501)
has interface assertions and malformed process output;
[Ubuntu](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43181405574/job/131058021415)
times out during post-test directory setup with the minimal HTTP C2 profile.
Their causes remain unverified and are separate from the successful local Salt
matrix. The completion-control changes were not part of that CI head.
