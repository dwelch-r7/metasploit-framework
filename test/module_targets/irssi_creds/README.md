# Irssi credential collection target

This opt-in profile exercises `post/multi/gather/irssi_creds`. The
profile uses pinned genuine Irssi 1.2.3/ngIRCd 26.1, a real host Framework console
and ordinary PostgreSQL reporting. Native clients run in actual PTYs; rawlogs
prove that file credentials produce 001 welcome or genuine password rejection.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb irssi_creds
```

Seven cases cover plain/repeat, tabs, compact assignment, commented secret text,
ordinary-user collection, a present but unreadable file and a password-free file. Each home file has its own real native
client gate before the actual owning call. The unreadable case authenticates at
0600, changes the file to 000 and proves the ordinary session sees an existing
file with a nil read; it is not a file-disappearance race. Raw loot and source/session file
bytes are verified; existing behavior does not create credential cores. No
NickServ success is claimed by this server-password profile. The separate
[NickServ target](../irssi_nickserv/README.md) supplies genuine IRC services
and its own authentication controls.

One serial stack has two capped containers: target 512 MiB/0.5 CPU and reporting
384 MiB/0.25 CPU, with equal memory/swap, PID128 and init. The Framework console
runs on the host; published ports bind only to loopback. Native client homes,
remote sessions, generated payload copies, home configs and Docker resources
must recover before qualification. Initial nickname and denial-observer failures
are preserved separately; other versions/platforms/grammar remain unqualified.
