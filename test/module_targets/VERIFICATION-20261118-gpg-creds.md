# GnuPG collection and home-path repair, 2026-11-18

Qualified [post/multi/gather/gpg_creds](../../modules/post/multi/gather/gpg_creds.rb) with **ten passing functional cases, CLI exit 0 and successful teardown**, reaching **290 runtime owners in covered paths, 585 qualified profiles and 4,078 historical functional cases**. Twelve actual calls use ten genuine sessions and save 38 exact raw GnuPG files. Baseline, replay, native prerequisites, units and the six-case environment regression are not added again. The broader campaign remains active; no PR is created.

## Reproduction and native prerequisites

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gpg_creds
```

The [target guide](gpg_creds/README.md) keeps the Docker/Compose fixture, native controls and automated tests together in the repository. Digest-pinned Ubuntu 22.04 installs GnuPG/gpg/gpg-agent/gpgconf `2.2.27-3ubuntu2.5` and Python `3.10.6-1~22.04.1`. A real host Framework console reports through an ordinary PostgreSQL role with an initially empty schema. There is one serial two-container stack, with target 512 MiB/0.5 CPU and reporting 384 MiB/0.25 CPU, equal memory/swap, PID128/init and loopback-only published ports.

Native CLI controls generate genuine Ed25519 signing keys under actual root and ordinary UIDs, following the official [GnuPG key-management interface](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html). Each key signs a real file and produces a matching VALIDSIG verification. Protected controls stop the actual agent/cache before requiring wrong-passphrase signing to fail. The fixture records real fingerprints, keygrips, binary/package versions and complete file bytes/hashes/UIDs/modes; it does not check in opaque key blobs. A separate single-container prerequisite cohort passes all four actor/protection combinations and removes its native agent processes, temporary directories, container and network, without any owner calls.

Functional cases create real keyrings in account homes, including `/home/lab space`, before actual owner execution. The explicit empty boundary file is added after valid native generation. Permission cases change only the private-key mode to 000 after successful signing/verification, then prove its unreadability as the actual session UID. Missing-keyring controls independently check every passwd/home candidate. Genuine Framework-generated `cmd/unix/reverse_bash` and `linux/x64/meterpreter_reverse_tcp` callbacks prove the actual kernel actor/PID and loaded owner path/hash. The shell reports Unix metadata on the physical Linux/amd64 target; Meterpreter reports Linux. No session, filesystem or reporting transport is doubled in the functional profile.

## Confirmed defect and unchanged owner-only replay

Original owner SHA256 is `cd2b81753dbc0e9a7abf193d0a36dd13eba345abff1bff29cbbb794b89f638d6`. Its directory listing interpolates the home path into an unquoted `ls` command. On the native-valid space-containing home, both session types split that path; the returned ls diagnostics are treated as filenames and no files are stored.

The clean original run `20261118T041004-31947a` has **4 examples/2 failures**, zero pending/outside errors, six calls and four genuine root sessions. Normal root collection and both same-instance repeats each save the expected four files, for 16 raw loots. Each space-home call saves zero rather than four. All 12 native cryptographic controls, selected file/session recovery and Docker teardown pass, with no operator channel close or process signal.

The one-line repair uses `create_process('ls', args: ['-1', path])`, reusing Framework's argument serialization, output capture and cleanup for both session types. Discovery, filtering and raw-loot metadata remain unchanged. Fixed run `20261118T041953-487d6a` passes **4/0**, saving all 24 expected files. **Exactly one of 58 inputs changes: the owner; all 57 spec/fixture/helper inputs remain identical.** Both cohorts pass the complete native/session/recovery audit. Fixed owner SHA256 is `61de937297924e62974b8229bc077164b98ceb4b6500891fda230af487cc4096`.

Focused contracts run the real owner and Post::Common helpers against actual host temporary paths and ls, with disclosed shell/Meterpreter transport adapters, file-access, output and persistence doubles. Original **21/8** becomes **21/0 twice**, and the parent independently passes **21/0** after import. Every cohort has zero pending, outside/support examples and outside errors. Spaces, single/double quotes, semicolons, UTF8, binary raw bytes, metadata, skipped directories/empty files, missing/empty homes, repeat and timeout restoration are covered. These contracts do not qualify remote sessions or GnuPG cryptography. Syntax, scoped RuboCop, msftidy and whitespace checks pass.

## Preserved fixture failures

Initial run `20261118T035925-7d293f` fails all four GPG examples before any session or owner call: the image lacks the session-payload copy directory. Native keyring controls and recovery pass, and Docker teardown succeeds. Its preceding shared-helper environment regression passes **6/0**, with eight actual calls/loots, six genuine sessions, complete selected recovery and no new channels or operator signals. The helper changes only derive the active owner source path and include the loot info column; its validated hash remains unchanged in final GPG inputs.

After adding the directory, run `20261118T040603-53c055` exposes a missing artifact-cleanup helper mount. Its six owner calls show normal collection and the space-path failure, but all four examples fail with recovery errors. These traces remain separate from module qualification. Mounting the existing shared helper and checking every required helper, payload-copy directory and selected artifact absence early is followed by the fresh clean original/fixed pair above. Both initial attempts and their actual errors are sealed; none is reclassified as passing.

## Final aggregate

Run `20261118T042458-61e5ed` passes **10/0**, zero pending/outside errors, in **346.4 RSpec seconds**, including native controls and recovery.

| Cases, both session types | Examples | Calls | Raw loot |
| --- | ---: | ---: | ---: |
| Root normal keyring and same-instance repeat | 2 | 4 | 16 |
| Root collecting protected space-home keyring | 2 | 2 | 8 |
| Ordinary user collecting its protected space-home keyring | 2 | 2 | 8 |
| Ordinary user with natively unreadable private key | 2 | 2 | 6 |
| Genuinely absent keyrings | 2 | 2 | 0 |

All 38 loots match exact native bytes, type, info, content type and actual session address in real PostgreSQL rows/files. Credential-core counts stay zero. Nonempty readable root-level GPG files and `private-keys-v1.d` contents are collected; nested revocation-directory files are outside the owner's selected traversal. Empty files and unreadable private keys produce no loot. Both root repeats reuse their module instance and create distinct loot records. There are five genuine shells and five Meterpreter sessions, with six root and four ordinary users.

The final run passes **16** genuine cryptographic controls, including **10** protected/wrong-passphrase controls, rehashes **80** native file maps and observes **26** actual agent exits. All eight generated case keyrings are hash/UID/mode-verified before removal; both missing-keyring recovery calls independently remain absent. All ten actual session/launcher PIDs, payload copies, proof markers, environment selectors and database session rows recover. There are no new channels, live descendants or operator channel closes/signals; Framework finishes without sessions/jobs. Selected account/home/package/helper/health-service state agrees before/after. Logs, access times and the entire filesystem are not claimed unchanged.

All eight cgroup OOM/PID-limit observations remain zero, and at most two capped containers run. The PostgreSQL volume and both networks are individually absent after teardown; both Docker contexts are empty. All **58** final inputs match. The read-only final trace seal has **137 entries**, manifest SHA256 `901852bfe44cd3bb8b8cb230fc1a1e73abfa1c70a80059131f5b0bf151599053`. Native prerequisites, original/replay, fixture failures, unit contracts and the environment regression retain independent seals/audits.

## Remaining scope

The earlier environment checkpoint retains its separate `stdapi_fs` warning investigation. That warning is not observed in the GPG original/replay/final session or Framework logs; actual file/process APIs and selected owner calls pass. This does not establish universal session-feature compatibility. Other GnuPG/OS/architecture versions, BSD/macOS, legacy 1.x/2.0 layouts, further payload delivery families and transports, broader directory traversal, credential cracking/importing and transport loss remain unqualified. No human module Scenarios are invented. The broader campaign remains active; no PR is created.

The updated [acceptance checkout record](VERIFICATION-20261118-acceptance-checkout.md) retains earlier actual-source Mettle timeouts and subsequent Linux/macOS successes. A later SMB test/report pair proves the exact environment-checkpoint fork revision with 20/0. These CI observations do not invoke the GPG owner or add qualification cases.
