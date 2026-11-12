# Salt information collection lab

This lab uses the pinned genuine Salt 3000.1 image and unchanged daemon supervisor
from the [execution lab](../saltstack_rce/README.md). It adds generated RSA keys,
a roster, a compilable SLS declaration, nested pillar data and administrative
key-list entries. The default minion path resolves to the exact configuration of
one running minion. Both real minions remain connected to the real master.

```sh
# Once on a fresh checkout, build the shared source-pinned Salt image.
docker compose -f test/module_targets/saltstack_zeromq/compose.yaml build target
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  saltstack_gather_3000_1 saltstack_gather_3000_1_shell
```

Build the prerequisite Salt image using the collection lab instructions first.
The additional Debian `net-tools` package is pinned by version and SHA-256 in
`system-package.json`, derived from Debian's archived Bullseye package index.
Salt needs its real `ifconfig` utility to enumerate this slim image's interfaces.
No Salt implementation is patched.

Native CLI/API controls must pass before the post module is judged. The ordinary
handler's exact generated payload is started through authenticated Salt RPC;
this session setup does not test unauthenticated exploitation. Functional tests
cover default collection, individual collection flags, a selected minion, and
repeated default/inventory collection on both declared session types. They retain actual console output, loot bytes,
reporting database records and session identity evidence.

Roster addresses use TEST-NET-1. The roster is inventory input: this lab does not
contact SSH services or establish that collected credentials authenticate. Pending,
rejected and denied key entries are valid public keys deliberately placed in
Salt's administrative stores, not additional authenticated or rejected daemons.
SLS data is compiled with `state.show_sls`; it is never applied.

The guarded serial launcher permits only one campaign project at a time. The
three containers total 1,408 MiB/1.7 CPUs, with bounded task counts and temporary
runtime state. It removes its containers and network when testing finishes.
Registration is not qualification: consult the
[campaign verification report](../VERIFICATION-20261112-saltstack-gather.md)
for actual results. Linux with co-installed master/minions is the current target;
Windows, macOS, FreeBSD, separate hosts and other Salt versions remain unqualified.
