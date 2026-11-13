# libssh authentication-bypass verification — 2026-11-13

## Summary

**229 modules qualified in covered paths, 265 profiles and 2,514 functional
examples.** The inventory contains 5,179 source files, 231 registered sources,
274 pending documented container hints and zero stale reviews. The broader
campaign remains incomplete. No pull request is created.

This checkpoint qualifies `auxiliary/scanner/ssh/libssh_auth_bypass` through the
[source-built lab](libssh/README.md). It repairs incomplete delayed output,
leaked SSH connections, false vulnerability reports before channel proof,
missing service association and refusal of genuine versionless libssh banners.
The [vendor advisory](https://www.libssh.org/security/advisories/CVE-2018-10933.txt)
identifies the server-side message-52 bypass and fixes in 0.7.6 and 0.8.4.

The complete frozen replay **`20261113T214003-d127a4` passed all 23 cases**, with
zero failures, pending cases or outside-example errors. It made **48 public
module calls**, verified **18 exact command-file proofs and ten complete real
Shell lifecycles**, and passed **94 independent native controls**. Controller,
manager and independent observer exited zero; their PIDs are absent. Elapsed
wall time was 352 seconds including cached image setup, a fresh console and
teardown; initial compilation/calibration costs are separate.

| Covered path | Cases | Public calls |
| --- | ---: | ---: |
| Execute on both affected branches, PTY on/off | 4 | 8 |
| Delayed Execute output | 1 | 2 |
| Real Shell on both branches, PTY on/off | 4 | 8 |
| Alternative `/bin/sh` session | 1 | 2 |
| Fixed Execute with banner gate on/off | 4 | 8 |
| Fixed Shell with banner gate disabled | 2 | 4 |
| Genuine versionless affected banner | 1 | 2 |
| Custom banner with gate on/off | 2 | 4 |
| Application-level callback refusal | 1 | 2 |
| Unrelated SMTP and refused port | 2 | 4 |
| Repeated reporting on two ports of one host | 1 | 4 |

The two isolated source commits `920a31979f0c3bb6a0e2d7b4620a1543e0094ce0` and
`dfc71984a2cfd6511b7c58e21a45aa53d48b50c4` were imported as
`d6ad0b57da6` and `80d69569b8e278aeb674bb5f1254860dc3db31b1`.
The final module SHA-256 is
`0c0a63cc2bba6ff6535ebcebcf0bc5a1fcc42c25adb26be99295a374160d2ec7`.
The lab/guide commit is `47b10472dcd648f19b4aee68b59957ab84446779`. All **59 selected input hashes** remain
current after committing it; the actual run selected those bytes at
`80d69569b8e278aeb674bb5f1254860dc3db31b1`.

## What looks good

Four checksum-pinned upstream SDK archives build on a digest-pinned Ubuntu
22.04 image: affected 0.7.5/0.8.3 and fixed 0.7.6/0.8.4. SDK authentication code
is unchanged. The upstream server example runs with the existing Framework
callback/shell patch or its original application authentication flag; only
public API banner configuration and disconnect lifetime guards supplement the
example. Sources and recipes are committed, not opaque target binaries. Old
compiler global-symbol semantics require `-fcommon`; crypto checks remain enabled.
Installed distribution packages and 16 binary/library hashes are recorded.

Seven SSH listeners cover the four versions, versionless/custom banners and an
application guard; a real SMTP listener supplies an unrelated protocol. Native
Paramiko controls reject wrong passwords and channels without message 52,
exercise legitimate password exec/shell, then send the actual raw bypass packet
without credential authentication. Successful commands create exact bytes as
UID 10001 and return real PID/UID/TTY. Fixed SDKs deny bypass channels. The guarded
application demonstrates that library bypass proof can coexist with an exec or
shell refusal. Both 47-case phases preserve provider process birth identities,
SDK/profile configuration, binary manifest and package fingerprint.

An initial native failure was a test-client encoding incompatibility: stock
Paramiko 2.9.3 rejected a genuine 255-byte RSA signature for a 256-byte key.
Independent modular-exponentiation/PKCS1-SHA1 and cryptography checks verified
the captured signature; a tampered signature was rejected. The lab zero-extends
that encoding before the unchanged verifier, following
[upstream handling](https://github.com/paramiko/paramiko/blob/3.5.1/paramiko/rsakey.py).
It neither skips signature verification nor counts this as a module defect.

Owning tests invoke the real console; no owner method or response is replaced.
Execute waits for channel completion under the configured deadline and retains
all stdout callbacks. Shell waits for readiness through an owner-local stream
observer, leaving the shared stream implementation unchanged. A confirmed opened
channel is required before reporting; an application's later callback refusal
still preserves real library-bypass evidence. Reporting occurs outside network
rescue, preserving unexpected reporting errors. Both fixed branches produce no
false finding with banner checking disabled, for either action.

The parent independently correlates raw native/SQL observations, every exact
file/UID proof, session owner/peer, all ten SQL session closures and all selected
input hashes. Repeated reports retain two distinct SSH service/vulnerability
identities on ports 2222 and 2224 of the same host. Each real Shell executes a
command, closes its remote process/socket, then uses the public session close
API and verifies registry/SQL closure. Generic CommandShell registration does
not itself consume remote EOF. Framework jobs and sessions return empty.

The first console is independently verified cold, with both freshly generated
metadata files and current source. Only three capped containers run: target
256 MiB/0.5 CPU/128 tasks, Framework 768 MiB/1.5 CPUs/256 tasks and PostgreSQL
128 MiB/0.2 CPU/64 tasks. Combined RAM is 1,152 MiB and CPU quota 2.2; swap limits
equal RAM and publication binds only to loopback. Every recorded memory/PID event
value is zero. All **eight independent final cleanup queries pass**, covering
three exact container IDs, one network, project labels and global inventory.

## Concerns

The complete earlier failed runs are retained. Initial build anchor/compiler/
legacy-linkage/C90 issues were target setup failures. The first functional run
also passed an empty CMD instead of leaving it unset; its Shell failures were
not attributed to source. A corrected run proved Shell operation but assumed
remote EOF would unregister a generic session; that control now explicitly uses
the public close API after observing remote closure. The initial baseline's
later failures shared its leaked connection and were not counted as separate
defects. The corrected harness stops at that boundary. The first fixed
complete replay genuinely passed 17/21 cases and exposed the four remaining
banner/reporting failures; the final replay closes those findings.

Focused synthetic owner regressions are separate from native qualification.
The first repair used the same 20 owner cases: 16 failures before, zero after;
seven shared helpers passed. The final reporting suite has **40 owner cases**:
14 expectation failures before, zero after, with the original 20 bodies unchanged
and passing and seven helpers passing. Fixture-loader/expectation diagnostics
and superseded checks remain labeled. All checked source/spec bytes match the
imported files. Syntax and module tidy pass. Strict module lint retains six
legacy findings versus eleven before, with zero new findings; acceptance Ruby
and the focused spec pass strict lint. Guide tidy retains eight identical
legacy warnings, with no new warnings.

This covers the selected Linux/amd64 SDK/example configuration, not every
libssh release, application callback implementation, operating system or crypto
backend. No native claim is made for the earliest 0.6 releases. Distribution
package repositories are not snapshot locked. Existing stdout-only/blank-output
semantics and `SSH_TIMEOUT=0` disabling the deadline remain; more extensive
command-output and timeout permutations are not claimed by the remote cases.
Previously deferred `druid_js`, `freeswitch_batch`, `superset_rce_owner` and
`wordpress_admin` profiles remain unqualified. Other candidates and the broader
goal remain open.

## Suggestions

Continue valuable container-feasible modules with independently calibrated
native controls, capped serial runtimes and complete cleanup. This module's
covered paths now pass; failures were classified before source repair.

Immutable local evidence under `~/.codex/reports/`:

- `libssh-native-signature-failure-20261113`: complete pre-Framework native
  failure and six successful cleanup queries; individual service logs were not
  collected in that first run, an explicit evidence limit.
- `libssh-native-rsa-client-diagnosis-20261113` and
  `libssh-native-controls-qualified-20261113`: independent signature diagnosis,
  tampered negative, SDK/provider controls and cleanup.
- `libssh-first-functional-baseline-20261113` and
  `libssh-corrected-command-baseline-20261113`: complete failed runs, all selected
  inputs and separate fixture/source classification.
- `libssh-first-fix-functional-20261113`: complete 21-case/four-failure run,
  94 native controls, ten Shell lifecycles and eight successful cleanup queries.
- `libssh-bypass-command-cleanup-fix-20261113-920a31979f0`: 114 worker manifest
  entries, independently rehashed; manifest
  `4893d27b73ec38d967d691657e8c50f55d72539a299c5420517ba23a76e318d8`.
- `libssh-bypass-proof-reporting-fix-20261113-precommit-0c0a63cc2bb`: 128 worker
  manifest entries, checked source/diff sealed before commit and independently
  rehashed; manifest
  `804493710f44454c8f994742c74132a8a88784029c1ab6658c848e329c865f1a`.
- `libssh-qualified-20261113`: **241 individually rehashed entries
  and 59 selected inputs**, including the complete passing run, source archives,
  native/SQL/session observations, parent audit, resource and cleanup receipts.
  Manifest SHA-256 `081c99b89f4c12f3dd28bed0b26be34fc4d9f870b808145a76dd13d9430bb22b`.

AI tooling prepared the lab, tests and report; isolated source-fix work repaired
the owning module. Shared Framework libraries are unchanged. The existing human
`## Usage` through EOF remains byte-exact, SHA-256
`26753e8405273cde4387654cef867aa82efb348959e120f016d40f9f8785b7ba`.
