# Irssi NickServ collection target

This opt-in profile exercises `post/multi/gather/irssi_creds` with genuine Irssi
1.2.3, ngIRCd 26.1 and Atheme 7.2.12 on digest-pinned Ubuntu 22.04. Native PTY
clients read the exact fixture files. IRC rawlogs independently prove IDENTIFY
and STATUS results; neither client nor server has an IRC server password that
could substitute for the NickServ secret. A genuine host Framework console,
Linux shell callbacks and ordinary PostgreSQL reporting execute the owner.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb irssi_nickserv
```

Nine cases cover lower-case IDENTIFY with same-instance repeat, caret command,
capitalized service nickname, explicit account arguments, command capitalization,
wrong credentials, commented text, a password-free file and an ordinary user's
own home. Every installed home file has a native client control before the owning
call. The suite checks exact printed single-argument secrets or complete
multi-argument authentication data, actual raw-loot records/files and zero
credential cores. Services differ in account/password argument order, so the
collector preserves multi-argument IDENTIFY text without guessing a password.

Wrong and commented credentials remain potential raw evidence; collecting them
does not establish successful authentication. The password-free file must
produce no loot. Independent root and ordinary-user native controls cover all
eight files before and after owning execution. The suite registers a real
NickServ account, then drops it through the real confirmation challenge and
verifies absence. Selected service/file state, exact source/session bytes,
home recovery and session/payload cleanup are checked.

One serial stack uses two containers: target 512 MiB/0.5 CPU and reporting
384 MiB/0.25 CPU, with equal memory/swap, PID128 and init. The Framework console
runs on the host; published ports bind only to loopback. The runner removes its
containers, database volume and networks. All native/Framework pipelines stay
serial. Run the existing server-password regression in the same serial command:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb irssi_nickserv irssi_creds
```

See the [verification report](../VERIFICATION-20261118-irssi-nickserv.md) for
actual results and retained setup/module failures. Other services, versions,
platforms, inline owning commands and further escaping/grammar need separate
qualification. Unit variants and native prerequisites do not add functional
cases to the campaign totals.
