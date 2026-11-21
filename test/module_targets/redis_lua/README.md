# Redis Debian/Ubuntu Lua sandbox escape

Run these profiles serially from the Framework root:

```sh
MODULE_TARGET_NAMESPACE=my-redis-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb redis_lua redis_lua_open redis_lua_fixed
```

Each profile uses one digest-pinned official Ubuntu Redis image, `linux/amd64`,
UID 101, a read-only root, 128 MiB memory/swap, 0.5 CPU and 64 PIDs. A random
loopback port exposes Redis; ephemeral tmpfs mounts cover `/tmp` and the image's
declared `/data` volume. The runner names/labels each project and removes it on
all exits. No image builds, package installs, privileged containers or host
Docker socket are needed. Only one profile runs at a time.

| Profile | Package | Authentication |
|---|---|---|
| `redis_lua` | Ubuntu `5:6.0.11-1` | `module-target-redis-password` |
| `redis_lua_open` | Same package | None |
| `redis_lua_fixed` | Ubuntu `5:6.0.16-1ubuntu1` | Same lab password |

The affected image was published as `ubuntu/redis:6.0-21.04_edge`, pinned at
`sha256:87f8d34dc0ae79bc3019b91bd008098d3b820e7e395e1e603f92b82ce5ce5f04`.
The patched image was `ubuntu/redis:6.0-22.04_edge`, pinned at
`sha256:2c4d16894f7b3d3edbe726f0df50e812a40f11f7bbc918682dedb00cf36a9731`.
These exercise distro packages linked to Lua; the existing upstream Redis
profiles do not reproduce this packaging vulnerability. See the
[original research](https://www.ubercomp.com/posts/2022-01-20_redis_on_debian_rce),
[Ubuntu advisory](https://ubuntu.com/security/CVE-2022-0543) and
[Debian advisory](https://lists.debian.org/debian-security-announce/2022/msg00048.html).

Before invoking the owner, stock `redis-cli`, `dpkg-query`, binary/library hashes,
Lua arithmetic and invalid-script controls establish the actual service. Native
unauthenticated, incorrect-password and valid-password requests establish access
independently of CLI exit status: Redis errors can still exit zero. Exact plain
and quoted Unicode/CRLF commands execute directly through the stock shell, then
through real Lua `package.loadlib` and `os.execute`, with independently read file
bytes and UID 101. On the patched package the shell still works, arithmetic still
works, `package` is blocked and the same Lua command creates no file.

The original owning module is observed passively. Repeated checks, credential
recovery, missing-library recovery, generic command delivery with AutoCheck on
and off, and patched AutoCheck refusal retain strict result/proof assertions.
The untouched default Bash payload is exercised before generic payload overrides
because msfconsole remembers a selected module's datastore. A stock handler/CLI
session must work first; two default owner sessions then run on one selection.
Actual post-bootstrap readiness, fresh shell replies, physical proof, PID/birth,
UID, graceful exit and two-peer callback closure gate session success.

Every profile preserves the complete Redis configuration, exact serialized keys
in databases 0 and 2, daemon PID/birth, all UID 101 processes and a foreign file.
The short-lived exact health-check helpers are excluded from process comparisons;
payload shells and reparented children remain included. Kernel TIME_WAIT and
inode-zero socket residue are distinguished from live/half-closed callbacks.
Script-cache entries and runtime counters naturally change when Lua runs; their
preservation is not claimed. Memory and PID limit events must remain zero.

The [verification report](../VERIFICATION-20261121-redis-lua.md) records the
passing repaired profiles, original failures and separate harness corrections.
The owner now uses binary RESP arguments and reason-bearing expected-failure
checks; its targets, payload defaults and shared libraries remain unchanged.
Assertions that originally caught the defects stay enabled. Owner examples are
withheld until every native readiness/resource/preservation guard succeeds.
Linux dropper, wget installation, alternate payloads, ACL usernames, TLS,
systemd `MemoryDenyWriteExecute`, other releases/architectures and database
reporting remain separate coverage work.
