# Irssi configuration collection and whitespace repair, 2026-11-18

Qualified [post/multi/gather/irssi_creds](../../modules/post/multi/gather/irssi_creds.rb) with **seven passing functional cases in one aggregate with exit 0**, reaching **288 runtime owners in covered paths, 582 qualified profiles and 4,053 historical functional cases**. The broader campaign remains active. No PR is created.

## Reproduction and independent prerequisites

Run `bundle exec ruby tools/dev/run_guarded_module_target_tests.rb irssi_creds`; the [profile guide](irssi_creds/README.md) describes the target. Digest-pinned Ubuntu 22.04 installs Irssi `1.2.3-1ubuntu4`, ngIRCd `26.1-1` and Python `3.10.6-1~22.04.1`. Actual package versions and both images' Linux/amd64 platform are observed. A separate ordinary PostgreSQL reporting role starts with an empty schema; the real host Framework console creates its schema.

Genuine Irssi runs in a PTY and reads each exact configuration. `/connect -rawlog ... LabNet` selects its configured chat network/server without supplying a password or protocol override. Actual rawlogs must show an IRC 001 welcome after the configured PASS, or ngIRCd's captured password rejection. Both root and ordinary-user controls accept plain, tab-separated and compact assignments; wrong passwords, a missing password and a commented password are rejected. The standalone native cohort passes 24 controls: twelve welcomes and twelve denials. Every client exits normally, its process disappears and its temporary home is removed; configuration bytes remain unchanged. Native acceptance is a prerequisite, not an owning collection result.

Each owning case installs its hash-checked mode-0600 file in a real user home and runs the same native client against that actual path. The unreadable case authenticates first, changes the ordinary user's file to mode 000, and separately proves that the genuine shell sees an existing file but cannot read it. Framework generates and runs genuine ELF shell payloads with actual callback, UID/PID and session/database proof. Active owner source path/hash and actual remote file bytes/readability must agree with the installed case. The owner declares only shell sessions.

Actual PostgreSQL loot records and host files are checked as exact raw configurations. This owner stores raw evidence rather than credential cores; all core counts must remain zero. Reusing the unchanged Rsync shell/callback/reporting/recovery helper does not imply a fresh replay of earlier profiles. Password-looking text in a comment or invalid credential remains collectible raw evidence; no active-authentication or successful-login reporting claim is made.

## Confirmed defect and owner-only replay

Original owner SHA256 is `d597b80c5b51d77e068b88838dd9334e66339317eb431591aa73c0aa746dc85a`. Run `20261118T005256-d3e1e2` has **4 examples/2 failures**, no pending/outside errors, five actual calls and four genuine root shells. Plain collection/repeat and commented-text collection pass. Tab-separated and compact assignments authenticate with native Irssi but produce no owning loot. Source and session file hashes agree; native controls, all four home/session recoveries and Docker teardown pass.

The narrow repair accepts whitespace around the network-password assignment and returns false for the nullable session read helper. It preserves existing inline/NickServ matching, output, raw loot type and metadata. Run `20261118T010305-5e51f1` passes **4/0** with the same five calls/four shells and now stores all five expected raw files. Exactly one of 50 declared inputs changes: the owner; all 49 fixture/spec/helper inputs remain identical. Fixed owner SHA256 is `a2b5d2d27207ca37c536b3089b47c6120991046289343b41972b50488469b39d`.

The identical focused spec produces **15 examples/4 failures** on the original, **15/0** on the repair, and **15/0** again; the parent independently passes **15/0**. Zero unrelated support examples run. Two original failures are the native-working whitespace files; two are synthetic nil-read contracts backed by the actual session-helper return contract. The final functional aggregate separately exercises a genuine permission-induced nil read. Exact native files and original raw loot supply fixture expectations. NickServ and inline compatibility strings remain unit-only. Transport, Framework access, persistence and output are doubled in that focused spec; actual owner detection/run logic executes.

Two initial native failures occur before any owner call: an overlong nickname is rejected with 432, then the first denial observer expects 464 while ngIRCd actually sends `ERROR :Access denied: Bad password?`. Original sources/results and cleanup outcomes are sealed before each correction. These are setup/observer failures and add no owning defect or passing qualification.

## Selected final aggregate

Run `20261118T010819-2c6a51` passes **7/0**, with zero pending/outside errors and successful teardown, in 208.5 RSpec seconds including prerequisites and recovery.

| Case | Shell user | Calls | New raw loot |
| --- | --- | ---: | ---: |
| Plain file and same-instance repeat | root | 2 | 2 |
| Tab-separated assignment | root | 1 | 1 |
| Compact assignment | root | 1 | 1 |
| Commented password text | root | 1 | 1 |
| Ordinary user's own home file | labuser | 1 | 1 |
| Present but unreadable own file | labuser | 1 | 0 |
| Password-free configuration | root | 1 | 0 |

Eight owning calls use seven genuine Linux shells: five root and two ordinary users. Six distinct raw loot records/files match the exact installed bytes, expected loot type, content type, info and session address. Same-instance repeat creates a new loot record with identical bytes. All queried credential-core counts are zero. Both the unreadable and password-free calls complete without loot. The commented password is absent from the native wire and denied authentication while its raw configuration is intentionally collected.

The aggregate has **31 real native client invocations**: seventeen welcomes and fourteen expected denials. Before/after controls contribute 24; immediate installed-file controls contribute seven. Selected passwd/group/server/home/fixture maps, the live server PID, all seven home-directory and session/payload/marker recoveries, and eight zero OOM/PID-limit snapshots pass. All 58 declared inputs match; the database volume and both networks are individually absent, and Docker is empty. Native/unit/original/replay controls are not added again to functional totals.

## Recovery, resources and remaining scope

Only one stack runs: two capped containers totaling 896 MiB/0.75 CPU (target 512 MiB/0.5 CPU, reporting 384 MiB/0.25 CPU), with equal memory/swap, PID128 and init. The genuine Framework console runs on the host. Published ports bind only to loopback. Actual Docker limits and cgroup OOM/PID-limit counters are checked; native/Framework/RSpec pipelines remain serial.

Each home file is removed only after matching its expected bytes, and the otherwise empty owned configuration directory is removed. Graceful remote exit is requested, the launched process must disappear, stale Framework registrations are removed and database session rows must close. Only hash-checked target ELF copies and exact session markers are removed. Host-generated payload and collected raw loot remain private evidence. Framework ends with no sessions/jobs. Selected state matches before/after; logs, counters and the entire filesystem are not claimed unchanged. The database volume and both networks are independently absent after teardown, with Docker empty.

Runtime coverage is Linux/amd64 and the exact observed client/server versions. NickServ needs genuine IRC services and remains unqualified. Other platforms/architectures/releases, further quoting/escaping/spacing/case/multiple-server grammar, inline owning collection, absent-home owning calls and transport loss remain unqualified. Unit compatibility cases do not qualify those native paths. No human Scenarios are invented. The broader campaign remains active; no PR is created.
