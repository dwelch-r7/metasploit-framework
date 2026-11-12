# Salt master/minion session investigation — 12 November 2026

The [session lab](saltstack_rce/README.md) is **registered, not qualified**.
The existing checkpoint remains **210 qualified modules, 192 profiles and
2,047 functional examples**. This investigation does not add passing examples
to that checkpoint. No pull request is created.

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
using proof APIs. This correction still requires a fresh functional run.

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
owning selector examples. Real cold-session validation remains pending.

Future acceptance deliberately makes concurrent
minion Python sessions the first Meterpreter use and asserts Stdapi is unloaded.
Preloading a single session would conceal this case.

## Evidence and review

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

**Summary:** the minion selector defect is verified and corrected; this complete
session profile remains unqualified. **What looks good:** native prerequisites,
three target paths, repeated cleanup and SQL identity are independently proved.
**Concerns:** the loader correction and SDK helper still need successful
functional validation. **Suggestions:** retain the failed captures and require all
nine cases before increasing the checkpoint. Other Salt releases, separate hosts
and the remaining Salt modules are individually pending.

CI on the earlier published `9c17653681edcf3e1163907cd1751693d92516d6`
finishes with 62 successful checks, one skipped and one
[macOS Intel Mettle failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43167576037/job/131012941396).
Its network-interface assertions fail; the cause remains unverified. This is
reported separately from the Linux Salt session results and is not attributed
to the unpublished Salt RCE changes.
