# Irssi NickServ collection and detection repair, 2026-11-18

Qualified the NickServ path of [post/multi/gather/irssi_creds](../../modules/post/multi/gather/irssi_creds.rb) with **nine new functional cases**. A serial aggregate also passes the seven existing server-password cases: **16/0, zero pending/outside errors, CLI exit 0 and successful teardown**. This adds one profile for an already covered owner, reaching **288 runtime owners in covered paths, 583 qualified profiles and 4,062 historical functional cases**. Regression, native, baseline and unit cases are not added again. The broader campaign remains active; no PR is created.

## Reproduction and independent prerequisites

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb irssi_nickserv irssi_creds
```

The [NickServ target guide](irssi_nickserv/README.md) describes the reproducible profile. Digest-pinned Ubuntu 22.04 installs Irssi `1.2.3-1ubuntu4`, ngIRCd `26.1-1`, Atheme `7.2.12-1` and Python `3.10.6-1~22.04.1`. Matching package sources and official [Irssi automation documentation](https://irssi.org/documentation/manual/automation/) inform the fixtures and extraction contract. Runtime coverage is Linux/amd64 with a genuine host Framework console and ordinary, initially empty PostgreSQL reporting schema.

Real Irssi clients run in PTYs and read exact files with `/connect -rawlog ... LabNet`. No client/server IRC password can substitute for NickServ authentication. Native controls create a real account through REGISTER, observe IDENTIFY and an independent STATUS response, then DROP the account using the actual confirmation challenge and verify absence. Both OS users exercise eight files: five identify successfully; wrong, missing and commented credentials remain unidentified. Every owning file receives the same native control at its real mode-0600 home path. Installed configuration bytes, native wire data, active owner source path/hash and genuine session reads are independently compared.

A standalone native cohort passes 16 controls, with ten identifications and six expected denials. One earlier attempt has zero owner calls: observing privilege-dropped ngIRCd through `/proc/PID/exe` fails, and the actual server link also rejects its mismatched password. Both are setup/observer failures, preserved before repair. The qualified fixture records launched PIDs, kernel names, UIDs, start times and installed package-file hashes; it does **not** claim proc-exe attestation or add ptrace capabilities. A supported common link password resolves the server-link configuration. All clients exit normally, disappear and remove their temporary homes.

## Confirmed owner defects and causal replay

Original owner SHA256 is `a2b5d2d27207ca37c536b3089b47c6120991046289343b41972b50488469b39d`. Native-working quoted lower-case/caret commands print a password ending in `";`; capitalized `NickServ` is missed and produces no loot; an account-first command prints `labguest` as the password. Actual shell reads match the installed files, and all native prerequisites, session/home recoveries and Docker teardown pass.

The first original run `20261118T021121-824fea` records 4/4. Its two-argument verifier is revised to retain complete authentication data: services disagree on nick/password argument order, including the password-first OFTC form described by Irssi. No argument position is guessed. That initial evidence remains intact. A **fresh original baseline**, `20261118T022612-75aa6a`, reproduces **4/4** with the final assertions, five actual calls and four genuine root shells.

The narrow owner-only repair makes command/nickname matching case-insensitive and excludes quote/semicolon terminators. Single-argument IDENTIFY and existing network-password output remain compatible. Multi-argument IDENTIFY retains complete argument order/internal whitespace under `NickServ IDENTIFY authentication data`. Raw selection, nil-read handling, loot type/metadata and credential-core behavior remain unchanged.

Run `20261118T022948-6076ce` passes **4/0**, with five calls, four shells and five exact raw loots. **Exactly one of 63 inputs changes: the owner. All 62 fixture/spec/helper inputs remain identical.** Fixed owner SHA256 is `836d247fc12130ccf9981125a6a49e4a1b12ddf6ad309704b9ece8fe5eae941d`. The source-only comparison retains successful native authentication, 36 client controls, four home/session recoveries, zero credential cores, zero OOM/PID counters and teardown.

The same focused contracts yield **37 examples/14 failures** on the original and **37/0 twice** on the repair; the parent independently passes **37/0**. All 15 pre-existing contracts pass unchanged. Comparable cohorts contain zero pending/outside/support examples or outside errors. Initial support-loaded, filter-fallback and empty-filter attempts are retained and excluded. Session transport, Framework access, output and persistence are doubled in unit tests; actual owner logic executes. Exact native files/wire excerpts supply expectations. Password-first ordering, unusual whitespace and further command boundaries are disclosed synthetic compatibility variants, without native OFTC claims. Syntax, scoped RuboCop, msftidy and whitespace checks pass.

## Final aggregate and recovery

Run `20261118T023353-86861a` passes the following profiles serially:

| Profile | Cases | Owning calls | Genuine shells | Exact raw loot | Native controls | RSpec seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| NickServ | 9 | 10 | 9 | 9 | 41 | 272.4 |
| Existing server-password regression | 7 | 8 | 7 | 6 | 31 | 179.8 |

NickServ covers lower-case/repeat, caret, capitalized service, explicit account, command capitalization, wrong credentials, commented text, password-free content and an ordinary user's own home. Eight root shells and one ordinary shell execute ten calls. Same-instance repeat creates distinct raw-loot records with identical bytes. All stored records/files have the expected type, content type, info and actual session address; credential-core counts remain zero. The password-free case completes without loot. Wrong/commented secrets remain collectible potential evidence, while native STATUS denies identification. Collection does not establish successful-login reporting.

The 41 NickServ client invocations comprise 32 before/after controls plus nine installed-file controls: 26 identify, 15 are expected denials. All native processes exit normally without operator signals, temporary homes disappear and configuration bytes remain unchanged. Selected system/home/fixture maps and service identities match. All nine home/session/payload/marker recoveries and eight zero cgroup snapshots pass; Framework has no sessions/jobs. The server-password regression separately passes all seven prior cases, including genuine ordinary-user unreadability, with 31 native clients, seven recoveries and eight zero cgroup snapshots.

At most two containers run, in one stack: target 512 MiB/0.5 CPU and reporting 384 MiB/0.25 CPU, equal memory/swap, PID128 and init. Actual Docker caps are inspected; published ports bind to loopback. Both database volumes and all four networks are individually absent after teardown, and both Docker contexts are empty. All 74 NickServ and 69 regression inputs match, with a 90-file union. Logs/counters and the entire filesystem are not claimed unchanged.

The read-only combined evidence seal has 235 entries and manifest SHA256 `646701f42b8ccd0fb0cf1733107f656d78882e58820c88b88cdaec5fca82a0fd`; every copied entry is rehashed. Separate original/native/replay evidence is retained. No human Scenarios are invented.

## Remaining scope

Other platforms/architectures/releases and IRC services, escaped-secret/configuration grammar, inline owning commands, absent-home cases and transport loss remain unqualified. Password-first service ordering has a source-backed unit contract; only the tested Atheme ordering has native authentication evidence. The collector intentionally retains matching commented or invalid text as raw evidence. This is a narrow detection repair, not a complete Irssi parser. The broader campaign remains active; no PR is created.
