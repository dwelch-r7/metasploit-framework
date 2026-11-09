# Linux post-module target

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb linux_post
```

The actual digest-pinned Ubuntu 22.04 container supplies native Linux OS,
processes, files and commands. Its Python standard-library HTTP server is only
a readiness endpoint, published on a random loopback port. An independent native
client records OS/kernel/UID, actual configuration bytes, container markers and
an executable's real output before Framework runs.

The suite generates current Framework native Linux x64 command-shell and
Meterpreter payloads into the owned artifact directory, mounts that directory
read-only on the target and starts each payload through container exec. Handlers
listen only on the project network. This establishes genuine session APIs for
post-module tests; it does not qualify a network exploit or an SSH login.
No payload binary is committed, and the source worktree is not mounted on the
target. The generated artifacts and native launch commands are retained.

Both declared session types cover Docker detection, available command enumeration,
specialist/missing directories and exact configuration-file loot through
`post/linux/gather/checkcontainer`, `post/linux/gather/enum_commands` and
`post/linux/gather/enum_configs`. Session setup waits for Framework's completed
bootstrap event before issuing commands; listing a session alone is insufficient.
Absent optional configuration paths are checked natively before accepting
their expected diagnostics. The target runs sessions as root. Nonroot permission boundaries, other distributions,
non-Docker container runtimes and full-host kernel behavior remain unqualified.
See the [campaign](../CAMPAIGN.md) for actual results and the [shared guide](../README.md)
for evidence, fresh projects and cleanup.
