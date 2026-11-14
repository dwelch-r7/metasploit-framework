# Heartbleed verification — 2026-11-14

## Summary

**230 modules qualified in covered paths, 266 profiles and 2,554 functional
examples.** The inventory contains 5,179 source files, 232 registered sources,
273 pending documented container hints and zero stale reviews. The broader
campaign remains incomplete. No pull request is created.

This checkpoint qualifies `auxiliary/scanner/ssl/openssl_heartbleed` through the
[source-built lab](heartbleed/README.md). It fixes protocol framing in saved
memory, missing vulnerability records during key recovery, unsupported-certificate
errors and division by zero for an invalid key-status interval. The
[OpenSSL advisory](https://openssl-library.org/news/secadv/20140407.txt) describes
the affected 1.0.1 releases, 1.0.1g fix and compile-time workaround.

The frozen current recipe **`20261113T235514-734748` passed all 40 cases**, with
zero failures, pending cases or outside-example errors. It made **82 public
module calls**, passed **120 native heartbeat cases and 42 complete normal TLS
handshakes**, and independently verified **34 wire/loot comparisons and two
recovered-key signatures**. Controller, manager and independent observer exited
zero. RSpec took 552 seconds; cached setup and teardown brought wall time to
572 seconds. Initial compilation and calibration are separate costs.

| Covered path | Cases | Public calls |
| --- | ---: | ---: |
| Basic check, dump, repeated scan, fixed/disabled and refused targets | 6 | 12 |
| SSLv3, TLS 1.0, 1.1 and 1.2 on the last affected release | 4 | 8 |
| Partial ordinary and complete conditioned default-length responses | 2 | 4 |
| Multiple dumps and matching/empty filters | 3 | 6 |
| Key recovery, bounded failure, fixed SDK, ECDSA and status validation | 5 | 10 |
| Integer limits and zero leak count/payload | 5 | 10 |
| ECDSA memory dump | 1 | 2 |
| Six STARTTLS dialogs, affected and fixed | 12 | 24 |
| Unrelated genuine HTTP service | 1 | 2 |
| Distinct service/vulnerability identities on one host | 1 | 4 |

Isolated source commits `cb15970bcbdd5dc6e5a43894ffabe864d79e85ea` and
`dbe1c975b597c52541fde2839b627ec260f73a3c` were imported as
`332df763c10541678fe35a0725dba2c967f3c439` and
`9c00ad323aa9a30205bc9c65c9abba6281d8add0`. The final module SHA-256 is
`f7677d393860cb36dc9e83aadf73dff10d568fad5aa18e4f66cd668d279e396d`.
The lab/guide commit is `31c17b54e81a6a19ebb0dcd6c122e52bac8f82d6`.
All **52 selected input hashes** remain exact after committing it.

## What looks good

Official release-tag commit archives build affected 1.0.1d/1.0.1f, fixed 1.0.1g
and heartbeat-disabled 1.0.1f on a digest-pinned Ubuntu image. These archives are
identified as GitHub source snapshots, not original vendor distribution tarballs.
SDK heartbeat code is unchanged. Build/package records and separate manifests
cover twelve SDK binaries/libraries and four test-application binaries.

Ordinary providers run unchanged upstream `s_server`. The separate transparent
heap-conditioning application uses the public OpenSSL allocator hook to place a
fresh disposable RSA factor beyond a TLS buffer's requested size. The real SDK
must overread that memory; fixed/disabled builds reject it despite identical
conditioning. This verifies deterministic key reconstruction without claiming
production exposure frequency. RSA signatures are independently reverified with
the host OpenSSL CLI against the native certificate, not merely accepted because
the module prints a key.

An actual ECDSA provider verifies non-RSA behavior. SMTP, IMAP, XMPP, POP3, FTP
and PostgreSQL adapters validate their upgrade dialogs and forward bytes to real
affected/fixed SDKs. They generate no heartbeat responses. Independent clients
verify valid echoes, malformed requests and full TLS handshakes. The complete
90-case native matrix runs before module calls; a 30-case final pass retains
every provider, transport, fixed/disabled rejection, ECDSA and all 21 normal TLS
handshakes. Binary and certificate identities remain unchanged.

Owning methods execute through real console `check` and `run` commands, with
native database queries for actual loot and vulnerability rows. No owning method,
response, reporting or loot function is replaced. Passive capture reassembles TCP
and TLS records, excludes protocol framing and compares the same connection's
payload with its persisted artifact. Binary PostgreSQL negotiation evidence is
base64 encoded. Repeated reports retain two different service identities on one
host; successful and unsuccessful key searches preserve real exposure findings.

Service process identities, connections, Framework jobs and sessions return to
idle. A fresh first console and both metadata files are independently verified.
Only three capped containers run: target 256 MiB/0.5 CPU, Framework 768 MiB/1.5
CPUs and PostgreSQL 128 MiB/0.2 CPU. Swap limits equal RAM; publication binds to
loopback. Memory and process-limit events are zero. All **eight independent
cleanup queries pass**, including exact IDs, project labels and global inventory.

## Concerns

Failed attempts remain separate from source verdicts. SDK installation first
needed generated pkg-config files. Missing vendor checksum sidecars led to
explicit commit-archive pins. A small valid heartbeat was genuinely buffered
during the incomplete handshake; a causal larger-request control flushes both
exact echoes. The first conditioning application omitted SSL retry/BIO flushing,
and its next version copied only twenty bytes of a twenty-one-byte marker. Both
failed native attempts were sealed before correction, with zero module calls.

The first six-case run included an incorrect expectation that positive checks
create no vulnerability, an overly short response timeout and binary assertion
diff serialization. A corrected **6/1** baseline isolated framing; changing only
the owner among forty selected files yielded **6/0**, with exact own-wire dumps.

The expanded baseline was **40/7**: four examples exposed the three KEYS source
defects; three were harness errors. PostgreSQL's binary prefix broke JSON logging,
although independently reconstructed original loot already matched all 8,192
captured payload bytes. Python's malformed-TLS HTTP rejection supplied a 400 HTML
body without a status line. Corrected serialization and structural expectations
follow those captures. No case was removed. Redundant pre-case idle polling and
separate console registry queries were combined.

The first fully corrected **40/0** replay also passed the full 180 native-case
matrix but took 595 of the runner's 600 seconds. The current recipe removes only
redundant final TLS-version/length permutations, retaining the full preflight and
all owning cases. Its **40/0** replay takes 552 seconds with the unchanged bound.

Synthetic owner regressions disclose transport, certificate and key-export
doubles. Framing tests produced **20 failures before / zero after across 24 owner
examples**, plus seven passing helpers. The final **40 owner examples** produced
**10 failures before / zero after**, with the original 24 bodies unchanged and
seven helpers passing. Actual native RSA recovery is verified separately.
Syntax/module tidy pass. Strict lint retains 47 legacy owner findings versus 49
originally, with zero new/spec findings. New acceptance Ruby passes strict lint.
Guide tidy retains nine identical legacy warnings, with no errors/new warnings.

Coverage is the selected Linux/amd64 SDK configuration, representative affected
releases, RSA-2048 and P-256. It does not establish every release, architecture,
compiler, cipher, certificate chain/size, handshake fragmentation pattern, real
STARTTLS application configuration or XMPP domain-discovery path. Apt repositories
are not snapshot locked. Previously deferred `druid_js`, `freeswitch_batch`,
`superset_rce_owner` and `wordpress_admin` remain unqualified.

The prior published checkpoint's CI has a
[Mettle acceptance failure](https://github.com/dwelch-r7/metasploit-framework/actions/runs/43514542727/job/132192998264):
`post/test/file` timed out sending a move-file request under the minimal-URI
malleable profile, then missed its outer completion deadline. The build itself
succeeded; 50 of 51 acceptance examples passed. Its cause remains unverified;
this is not classified as a proven flake or attributed to Heartbleed.

## Suggestions

Continue valuable container-feasible modules with independent native/wire/SQL
controls, serial capped resources and complete cleanup. Investigate the remote
Mettle timeout separately if it repeats; retain its original result and cause
uncertainty. The overall module campaign is still open.

Immutable evidence under `~/.codex/reports/` includes the complete failed native
and functional attempts, both source-worker before/after archives, the full
180-native-case passing replay and the current qualified replay:

- `heartbleed-expanded-functional-baseline-20261113`: 481 entries / 51 inputs;
  manifest `1f5adadf9f79c1e03c6e2099ff15f8ca7a63414729e20e245c427b8228b58875`.
- `heartbleed-full-native-matrix-functional-20261113`: 522 entries / 52 inputs;
  manifest `195f7085176fed7bd675ac778f6d24bffabf139f80764f7398acb07336db9ed4`.
- `heartbleed-qualified-20261114`: **528 individually rehashed entries / 52 inputs**;
  manifest `748b3e4f63f254f4565b183a60b0fa8736a072091fa51b80ee7a8bc672c40ec0`.

AI tooling prepared the lab, tests, report and isolated source repairs. Shared
Framework libraries are unchanged. The original human `## Scenarios` through EOF
remains byte-exact, SHA-256
`f8be4ae1ef032eb7a828c02856294575133aed67438f2a24e58ea8349a0069e1`.
