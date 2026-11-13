# FreeSWITCH event-socket login verification — 2026-11-13

## Summary

The [serial lab](freeswitch/README.md) qualifies
`auxiliary/scanner/misc/freeswitch_event_socket_login`. The current campaign
reaches **225 modules, 243 profiles and 2,357 functional examples**.
The broader valuable-module inventory remains open; companion execution paths
require separate qualification.

Tested revision: `2314bbe68406a77945c166c11f532c0f7596c51c`. Final run: `20261113T123725-081191`.
The final controller, manager and observer exit 0. All **25 cases and 50 public
module calls** pass, with zero pending cases or errors outside examples.

| Profile | Cases | Public calls |
|---|---:|---:|
| Explicit conventional password `ClueCon` | 9 | 18 |
| Unicode password containing a space | 9 | 18 |
| Loopback-only event-socket ACL | 4 | 8 |
| Unrelated real OpenSSH server | 3 | 6 |

## What looks good

The original Drachtio image is pinned to its Linux amd64 manifest. The running
engine reports FreeSWITCH 1.10.10 and commit prefix `4cb05e7f4a`, resolved to
upstream commit `4cb05e7f4a23645ec387f3b5391194128be7d193`. Six recorded engine, library, module,
client and entrypoint hashes match before and after testing. Original upstream
source and vendor build references are retained. They do not establish a
reproducible source-to-binary build match.

Normal event-socket and ACL configuration files are used. The lab sets its
password explicitly, bypassing the image entrypoint's duplicate ACL definitions.
The restricted profile rejects external clients with the original framed
`text/rude-rejection` response while genuine local `fs_cli` stays healthy.
Wrong passwords fail; valid passwords authenticate and return the real version,
module-loading result and exact output from the original `system` API. Neither
responses, authentication nor ACL decisions are simulated. The unrelated SSH
server also passes its native password-login health check.

Public cases cover passive check, quiet/verbose output, explicit and default
passwords, a bounded candidate file, stopping after its first successful entry,
explicit-password priority, AutoCheck disabled, ForceExploit under ACL rejection,
unrelated services and a native-proven refused port. Each case runs twice.
Native refused-port controls execute inside Framework against the same target
container, rather than the host's separate loopback port. Passive capture in
Framework's existing namespace records real packets without replacing its sockets.

PostgreSQL rows verify the exact password, null username, successful status,
service/host/port/protocol and module origin. Repeat successes preserve one
credential core and login identity; attempt timestamps are present. Configuration
hashes and engine process identity remain stable, with no voice sessions,
Framework jobs or Framework sessions left over.

The original check exposed `Rex::ConnectionRefused` and a full backtrace from
both public check and AutoCheck. The isolated repair returns reason-bearing
Unknown results for expected connection/read failures and empty banners, and
ensures the existing TCP cleanup runs. Genuine authentication, ACL and unrelated
fingerprints retain their established classifications. Unexpected programming
errors and user interrupts remain visible; the specific Rex timeout class is
handled separately. The conventional port stays 8021 and operator overrides
are preserved. Shared Scanner/TCP/login/credential libraries are unchanged.

The identical focused 21-case suite, seed 509802, changes from
**14 failures / exit 1 to zero / exit 0**. Captured service banners,
owner initialization, classification and TCP disconnect bookkeeping are real;
socket establishment/read/shutdown/close operations and logging are doubles. Error/sentinel cases are
synthetic boundaries. The parent independently passes all 21 cases.
Container acceptance separately proves actual transport and persisted results.

Profiles run serially with **three containers**. FreeSWITCH profiles cap total
memory at 1,664 MiB, CPUs at 2.5 and tasks at 576. The OpenSSH profile uses
1,024 MiB, 1.9 CPUs and 448 tasks. Only target TCP is published on host loopback.
Declared log/recording/sound volumes are replaced with bounded tmpfs mounts;
reporting data is also temporary, with no persistent Docker volumes. No startup
packages or application dependencies are added to Framework.

The first console is genuinely cold; later profiles use only that invocation's
normal metadata. Actual prompts, BOOT records and both fresh cache files are
independently observed. All **32 independent final cleanup queries** pass.
Docker is empty, the guard exits 0, its PID is absent and its lock is free.
All final memory-limit, OOM and PID-limit counters are zero.

Reproduce serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/freeswitch/run.rb

SPEC_HELPER_LOAD_METASPLOIT=false bundle exec rspec \
  spec/modules/auxiliary/scanner/misc/freeswitch_event_socket_login_spec.rb \
  --seed 509802
```

Final evidence: 512 entries and 66 pinned inputs, manifest
`a811bef69bf020194aa2a506231fdaaf980651d8dd04e5bba6663c82e9eb83a9`. Parent-verified source comparison: 92 entries,
manifest `9a7635a4a6e3a4a8da523bc702799cf0b22f7140e7825c8949b96cd94ab3f492`. Copied hashes, read-only modes and single links
are verified.

## Concerns

The mixed baseline `20261113T120824-75c3a2` has 25 cases, eight failures and
42 actual public calls. Four failures are fixture encoding mismatches: its
binary console text was compared with UTF-8. Actual captured traffic, accepted
replies and SQL passwords were correct. The other four failures are the proven
closed-port check defect. The 442-entry mixed seal has manifest
`abdf5db86bc06bbf238af0fb89a836b324b68924b4b71c984c898046ee242949`.

After tagging a duplicate console string as UTF-8, unchanged-owner run
`20261113T121617-def3d9` has 25 cases, four source failures and 46 actual calls.
All Unicode repeat, credential-ordering, ACL and OpenSSH cases pass. Both failed
baselines have clean teardown and zero resource events. The 477-entry source
seal has manifest
`9f0aa10c8b208ea60e5f8b96443815f39e5ff3f1c8087e215b9e3f166bac0934`.
These remain separate from the final source-fix replay.

Early unit drafts incorrectly accessed protected TCP socket accessors and
remain separate. Their setup failures do not establish module defects. The ACL
frame also spans multiple real TCP packets; its projection uses the reassembled
stream, with both the actual header fragment and full frame tested. Only the
corrected, identical before/fixed spec supports the comparison above.
A task-local launcher naming typo failed syntax before any Docker or module
run; the corrected controller's actual process exits are retained. FreeSWITCH
reports that real-time scheduler priority is unavailable in this unprivileged
lab; functional controls succeed without granting additional capabilities.

Changed Ruby passes strict RuboCop, syntax and module/module-doc checks. The
whole historical Scenarios-through-EOF tail remains byte-exact, SHA-256
`2afbaffdd6a4a3c29840a488e64c2d08721fff319ccf6aae5460cc38169dca83`.
The full RSpec suite is not run. Older/newer releases, TLS/proxies, additional
password encodings, multi-host RHOSTS batches and VoIP/media workloads remain
unqualified. These login tests do not establish payload sessions or
delivery-family compatibility.

The preceding published revision `4c95ebfa9df3a97fe32667de1782715b73d18066` has
eight successful checks, one skipped, three in progress and 47 queued at
12:44 UTC. No failure is reported at that snapshot; it does not establish
completed CI acceptance of this new checkpoint. Remote CI is tracked separately.

## Suggestions

Verify multi-host RHOSTS behavior with independently controlled service states.
Then continue with the companion execution module's supported Linux paths,
including in-memory command/session and x86/x64 dropper families with actual
cleanup.
The stock image lacks curl/wget; genuine delivery prerequisites need their own
native verification before interpreting a payload failure. Windows targets need
a suitable Windows environment. Continue the rest of the valuable-module
inventory; missing container hints do not establish infeasibility. No PR is
created, and the three historical profile exclusions remain unchanged.
