# PostgreSQL password-file collection and repair, 2026-11-17

Qualified [post/multi/gather/pgpass_creds](../../modules/post/multi/gather/pgpass_creds.rb) with **16 passing functional cases in one aggregate with exit 0**, reaching **286 runtime owners in covered paths, 580 qualified profiles and 4,036 historical functional cases**. The broader campaign remains active. No PR is created.

## Reproduction and prerequisites

Use `bundle exec ruby tools/dev/run_guarded_module_target_tests.rb pgpass_creds` and the [profile guide](pgpass_creds/README.md). A digest-pinned genuine PostgreSQL target runs both server and client. Actual versions are server/psql 16.15, linked libpq 18.6, Debian 13.7 and Python 3.13.5. The separate reporting service uses an ordinary role and empty schema before Framework creates its real schema.

Native psql controls authenticate through exact mode-0600 files as root and an ordinary user; all inherited PG variables are removed. Wrong passwords, missing files and broad permissions are denied. Each selected home file also authenticates immediately before collection. No module parser, authentication response or owning result is simulated in functional tests.

Generated Linux x64 ELF payloads establish genuine shell/Meterpreter sessions. Payload execution is a collection prerequisite, not an exploit claim. Actual session metadata and the active owner's source location/hash and file read must match the native fixture. Reporting queries inspect stored credential cores, session origins, PostgreSQL database realms, Untried login rows and exact raw loot records/files. Native authentication does not change collection reporting into Successful logins.

## Original failures and causal replay

Original unchanged owner SHA256 `8a6bb9cd3375a93077d8da2cd7d49139852ba3a1fad85159c19d7c093dfd3034` reaches eight owning calls over three shells and three Meterpreter sessions in run `20261117T232431-be56eb`: six examples/four failures. Plain collection/repeat passes. A native-working blank line raises `NoMethodError` at password splitting. An escaped database delimiter stores username `db`, realm `pgpass` plus a literal backslash, and a shifted password. Both defects reproduce through each session type. All native gates and session/file/Docker cleanup pass.

The repair decodes backslash escapes while finding the first four field boundaries and ignores incomplete lines. Run `20261117T233253-37e320` passes the unchanged six examples/eight owning calls. Only the owner changes among 76 declared inputs; the other 75, including fixtures, spec and helpers, are identical. Fixed owner SHA256 is `ffb9411b7fef65d6a3d6c771493ec7dfb6432530e619a5fe0b9e2088ccdfa398`.

The identical focused spec produces 19 examples/eight failures on the original and 19/0 twice on the repair; an independent parent run also passes 19/0. No unrelated support examples run. Eight fixture files come from real native gates. Five extra escape/empty/trailing boundaries follow the [exact linked libpq `REL_18_6` source](https://github.com/postgres/postgres/blob/REL_18_6/src/interfaces/libpq/fe-connect.c) and have no native authentication claim. Transport, Framework/session metadata, persistence and output are doubled in these unit tests; owning parser/table/report argument construction is real.

Earlier configuration errors selected a non-internal endpoint network and then an unpublished internal-only port. A later mixed trial reached four owning shell calls but failed Meterpreter setup on an extra proof marker; late payload-hash capture also broke artifact cleanup. Its lingering marker contaminated following setup attempts. These setup/harness failures are retained separately from the clean original cohort. The corrected fixture reuses the existing bounded, native-observed Meterpreter marker and captures cleanup data early. No failing test alone is treated as an owner verdict.

## Final aggregate

Run `20261117T233749-390cc0` passes **16/0**, with zero pending/outside errors and successful teardown, in 413.6 RSpec seconds including prerequisites and recovery. Each of eight file variants runs through both declared session types on Linux:

| File variant | Shell cases | Meterpreter cases |
| --- | ---: | ---: |
| Plain file and same-instance repeat | 1 | 1 |
| Comments | 1 | 1 |
| Blank lines | 1 | 1 |
| Wildcard host/port | 1 | 1 |
| Escaped database | 1 | 1 |
| Escaped username | 1 | 1 |
| Escaped password colon/backslash | 1 | 1 |
| Incomplete line followed by a valid entry | 1 | 1 |

Eighteen actual owning calls use eight genuine shells and eight genuine Meterpreter sessions, all root. Direct database queries verify sixteen unique credential cores and sixteen Untried login rows with session origins, PostgreSQL realms, exact credentials and nil attempt timestamps. Eighteen distinct raw loot records/files preserve exact input bytes. Each same-instance repeat preserves the existing core/login and creates a new loot record with identical bytes.

The selected aggregate has **60 native SQL controls**: 48 actual authenticated successes and twelve denials. Thirty-two successes and twelve denials come from before/after root/ordinary-user controls; sixteen successes authenticate each installed home file immediately before collection. The exact-package standalone preflight separately passes 44 controls and is not added again to functional totals.

All sixteen home files, remote session processes and target payload/marker sets are recovered without operator signals. Database sessions close and Framework ends with no sessions or jobs. Twelve cgroup snapshots have zero OOM/PID-limit events. All three image IDs report Linux/amd64; all 86 declared runtime inputs still match. Both volumes and both networks are individually absent and no containers remain. Native/unit/preliminary/replay cases are not counted again.

## Resources, recovery and limits

One serial stack runs at most three work containers: target 512 MiB/0.5 CPU, reporting 384 MiB/0.25 CPU and Framework 1536 MiB/1 CPU, totaling 2432 MiB/1.75 CPUs. Memory/swap, PID128/128/256 and init limits are checked in resolved configuration and actual containers. Published database ports bind only to loopback; Framework uses the internal network. Cgroup OOM/PID-limit counters must remain zero.

Recovery matches installed home-file bytes before deletion, fingerprints the actual remote process before any optional signal, proves its disappearance and database closure, and removes only hash-checked generated target ELFs and session markers. Generated source payloads and collected raw loot remain intentional private test evidence. Selected file/fixture maps must match before/after; logs, counters and the whole filesystem are not claimed unchanged. Both database volumes and both networks must be independently absent after teardown.

Linux/amd64 root sessions and the exact observed PostgreSQL/client stack are the runtime scope. Windows/BSD/macOS, other architectures, ordinary-user owning sessions, other releases, additional grammar and transport-loss behavior remain unqualified. Source-backed IPv6, empty password and escape boundaries remain unit-only. Legacy collection of unescaped password colons is preserved; it differs from libpq and is outside native qualification. Human Scenarios are not invented.
