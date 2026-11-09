# Linux account history and password collection

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb linux_history
```

The family tests `post/linux/gather/enum_users_history` and
`post/linux/gather/hashdump`. The digest-pinned Ubuntu 22.04
[Linux session fixture](../linux_post/README.md)
provides genuine command-shell and Meterpreter sessions. Native `useradd` and
`chpasswd` create public artificial accounts and actual SHA-512 shadow records.
Root, an ordinary user and an account with a space in its home path have shell,
database-client and Vim history files. Empty Zsh history and absent C-shell
history provide distinct negative controls. System accounts remain intact.
The root-only sudoers file is a collection fixture; no sudo policy is exercised.
Actual empty wtmp/lastlog files exercise log collection, not login-event parsing.

Native Python reads exact bytes, verifies password hashes through libc crypt,
and checks root/nonroot read permissions before module execution. Eight cases
cover both session types as root and `labuser`, repeated current-user history collection,
exact passwd/shadow/unshadowed/history loot, locked-account exclusion and
nonroot hash-access refusal. All passwords and account data are public fixtures.
Each case has a fresh real session, which the common helper closes afterward.
Root history scans every native system account once per session type; hash collection and nonroot
refusal run twice. Session command output removes its final newline; only the
`last`/`lastlog` expectation accounts for that API contract. File bytes remain
exact. Framework database credential persistence is not qualified.

Only random loopback readiness ports are published; handlers stay on the isolated
project network. Generated payloads and native commands are retained by the
[shared runner](../README.md), which removes owned targets and volumes afterward.
Other distributions, shell implementations, account databases, hash algorithms,
real login-history records and protected-file ACL variants remain unqualified.
Registration alone is not a passing result; no human Scenarios are generated.
