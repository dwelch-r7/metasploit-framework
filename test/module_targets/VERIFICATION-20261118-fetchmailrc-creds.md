# Fetchmail credential collection and quote repair, 2026-11-18

Qualified [post/multi/gather/fetchmailrc_creds](../../modules/post/multi/gather/fetchmailrc_creds.rb) with **ten passing functional cases in one aggregate with exit 0**, reaching **287 runtime owners in covered paths, 581 qualified profiles and 4,046 historical functional cases**. The broader campaign remains active. No PR is created.

## Reproduction and independent prerequisites

Run `bundle exec ruby tools/dev/run_guarded_module_target_tests.rb fetchmailrc_creds`; the [profile guide](fetchmailrc_creds/README.md) describes the target. The combined target uses digest-pinned Ubuntu 22.04, Fetchmail `6.4.27-1ubuntu0.2`, Dovecot `1:2.3.16+dfsg1-3ubuntu2.9`, Python `3.10.6-1~22.04.1` and OpenSSL `3.0.2-0ubuntu1.30`. Actual package versions, native TLS and image platform are observed. A separate ordinary PostgreSQL reporting role starts with an empty schema; the real host Framework console creates its schema.

Genuine `fetchmail --check` reads each exact file, authenticates without retrieving/deleting mail, and verifies the explicit lab certificate. No credential/protocol CLI override supplies the answer. Dovecot's actual successful-login records must name every expected account, including both users in the multiple-user file. Root and ordinary-user controls accept eight file variants and reject wrong passwords, unsafe permissions and missing files. The standalone exact-package cohort passes 44 controls: 32 successful client invocations, twelve denials and 36 validated account checks. Message contents and selected file/fixture hashes remain unchanged. Native client success is a prerequisite; it does not qualify owning collection by itself.

Each owning case installs a hash-checked mode-0600 home file and authenticates that actual path as its owner. The selected shell user's native read permission is observed separately. Framework generates and runs genuine ELF shell payloads with native callback, UID/PID and actual session/database proof. The active owner's source path/hash and actual remote file bytes/readability must agree with the native case. The owner declares only shell sessions; payload execution is a post-module prerequisite, not an exploit claim.

Actual PostgreSQL loot records and host files are checked as CSV. This owner stores collected CSV rather than credential cores; all core counts must remain zero. Reusing unchanged Netrc CSV and Rsync shell/callback/recovery helpers does not imply a fresh replay of those earlier profiles.

## Confirmed defect and source-only replay

Original owner SHA256 is `c07ec8f5244394517d8a7a71037acc428c46c004551df6a527f90bb618cbb9b2`. Run `20261118T000207-0d3f9e` has **2 examples/1 failure**, no pending/outside errors, three actual calls and two genuine root shells. Plain collection/repeat passes. The native-working quoted password `module target password` is truncated to `module` in actual CSV. Session reads match the real native file; all native gates, both session/file recoveries and Docker teardown pass.

The repair extracts complete quoted credential values and prevents user/password keywords inside a quoted value becoming extra accounts. Run `20261118T001414-1c1bbe` passes **2/0** with the same three calls/two shells. Exactly one of 56 declared inputs changes: the owner. All 55 fixture/spec/helper inputs remain identical, and the actual CSV now contains the full password. Fixed owner SHA256 is `ef69d7e9f9387c5aac0dd5eec15a3fe15a177d59e201ce15c18f337777cb22b4`.

The identical focused spec produces **21 examples/6 failures** on the original, **21/0** on the repair, and **21/0** again; the parent independently passes **21/0**. Zero unrelated support examples run. Eight exact native files and a real original plain CSV supply capture-based expectations. Five extra quote/ESMTP boundaries follow the [matching 6.4.27 lexer/grammar](https://archive.ubuntu.com/ubuntu/pool/main/f/fetchmail/fetchmail_6.4.27.orig.tar.xz), without native account/authentication claims. Both quote styles occur in that source despite the newer manual's narrower wording. Escape bytes remain unchanged; Fetchmail's C/numeric escape decoding is not implemented or qualified. Unit transport, framework access, persistence and output are doubled; real owner parsing/default merging, table construction and CSV generation execute.

The initial native fixture placed a server timeout after user options and was rejected before any owning call. Its source/results are sealed before correction. A host-console Compose preflight also refused an unnecessary container-console artifact variable; no container or owner started. That snapshot is retained. Native temporary JSON now stays inside the owned target and observations return through existing command capture. These setup failures are separate from the genuine truncation defect.

## Selected final aggregate

Run `20261118T001832-50e648` passes **10/0**, with zero pending/outside errors and successful teardown, in 292.9 RSpec seconds including prerequisites and recovery.

| Case | Shell user | Calls | New CSV loot |
| --- | --- | ---: | ---: |
| Plain file and same-instance repeat | root | 2 | 2 |
| Quoted password with spaces | root | 1 | 1 |
| IMAP file | root | 1 | 1 |
| Comments | root | 1 | 1 |
| Blank lines | root | 1 | 1 |
| Multiline stanza | root | 1 | 1 |
| Defaults plus poll stanza | root | 1 | 1 |
| Multiple users | root | 1 | 1 |
| Unreadable root file | labuser | 1 | 0 |
| Ordinary user's own home file | labuser | 1 | 1 |

Eleven owning calls use ten actual Linux shells: eight root and two ordinary users. Ten unique CSV loot records/files contain eleven exact data rows; the multiple-user case contributes two rows. All queried credential-core counts remain zero. Same-instance repeat creates a distinct loot record with identical CSV bytes. The unreadable-root case returns no loot, while the same ordinary user's own file is collected correctly.

The aggregate has **54 real native client invocations**: 42 successful check-only runs and twelve expected denials. Those runs validate 47 account-login checks, including both users in multiple-user files. Before/after native controls are separate from each of ten immediate installed-file authentications. Message content, selected file/fixture maps, all ten home-file and session/payload/marker recoveries, and eight zero OOM/PID-limit snapshots pass. Both image IDs report Linux/amd64, all 67 declared inputs match, the database volume and both networks are individually absent, and Docker is empty. Native/unit/original/replay controls are not added again to functional totals.

## Recovery, resources and remaining scope

Only one stack runs: two capped Docker containers totaling 896 MiB/0.75 CPU (target 512 MiB/0.5 CPU, reporting 384 MiB/0.25 CPU), with equal memory/swap, PID128 and init. The genuine Framework console runs on the host. Published ports bind only to loopback. Actual Docker limits and cgroup OOM/PID-limit counters are checked; native/Framework/RSpec pipelines remain serial.

Each home file is removed only after matching expected bytes. Graceful remote exit is requested, the launched process must disappear, stale Framework registrations are removed, and database session rows must close. Only hash-checked target ELF copies and exact session markers are removed. Host-generated payload and collected CSV remain private evidence. Framework ends with no sessions/jobs. Selected passwd/group/configuration/fixture maps and Maildir message content hashes match before/after; logs, counters and the entire filesystem are not claimed unchanged. The database volume and both networks are independently absent after teardown, with Docker empty.

Runtime coverage is Linux/amd64 and the exact observed client/server stack. Other platforms/architectures/releases, native single quotes/quoted usernames, ESMTP authentication, escape decoding, additional metadata/comment/separator grammar and transport-loss behavior remain unqualified. Source-backed unit cases do not qualify those native paths. No human Scenarios are invented. The wider campaign remains active; no PR is created.
