# APISIX module targets

These fixtures run the stock APISIX releases and a real etcd daemon. The positive
session profiles also use the existing Framework reporting database fixture.
Run them from the Framework checkout with its normal Ruby dependencies:

```sh
export MODULE_TARGET_NAMESPACE=apisix-$(date +%s)-$$
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  apisix_2120_batch_open apisix_2121_direct \
  apisix_2120_direct apisix_2121_batch
```

The guarded launcher runs profiles serially, records image IDs and input hashes,
and removes each stack and its ephemeral resources before starting the next.
It also cleans up after failure or interruption. Keep the printed evidence path;
`runtime.json` contains the exact Compose project and ephemeral loopback ports.
The shared launcher lock prevents concurrent guarded stacks across worktrees.

| Profile | Configuration | Intended coverage |
| --- | --- | --- |
| `apisix_2120_batch_open` | 2.12.0, batch plugin, admin ACL allows the lab client | Batch checks, commands, Bash/Netcat sessions and repeats |
| `apisix_2121_direct` | 2.12.1, batch disabled, admin ACL allows the lab client | Direct checks, commands, Bash/Netcat sessions and repeats |
| `apisix_2120_direct` | 2.12.0, batch disabled, admin ACL allows the lab client | Direct checks and exact commands on the earlier release |
| `apisix_2121_batch` | 2.12.1, batch enabled, loopback-only admin ACL | Genuine access denial, safe check and refusal without mutation |

Images are pinned to digests and the tested `linux/amd64` platform. Each stack has
two or three containers: APISIX (384 MiB, 0.75 CPU), etcd (192 MiB, 0.25 CPU), and
optionally reporting PostgreSQL (384 MiB, 0.25 CPU). Only loopback ports are
published. The application and reporting services can reach the host callbacks;
etcd stays on the internal network.

`native.py` verifies the release, bundled source hashes, actual access controls,
independent exact-byte command execution and cleanup before owner tests. A
pre-existing route named `index` remains present throughout the owner cases.
The command oracle uses Lua `string.char` rather than the module's literal
encoder. Kernel resource counters are checked for the application and reporting
service; the unchanged distroless etcd image has no `cat`, so its Engine health,
restart and OOM state are recorded separately.

The session controls reuse the real Framework handlers, public session APIs,
SQL reporting and physical cleanup checks used by Kafka UI/Kong fixtures. The
expected UID and SDK execution user come from the stock APISIX worker identity.
Owner sessions must leave the Admin API responsive and remove their allocated
route before the session closes. Append-only command proofs and one actual
reported session per workspace detect duplicate execution. Listener refusal, remote process/FIFO/file
removal and database closure are checked after use.

CVE-2022-24112's restricted-admin bypass is a separate qualification. A stock
2.12.0 restricted configuration has produced both native success and native 403
on fresh instances. The installed HTTP library normalizes conflicting header
cases during table iteration, which offers an explanation for that variability;
exact worker iteration order has not been captured. The open-admin batch profile
qualifies batch execution and cleanup. It does not prove the restricted bypass.
The fixed restricted profile supplies a genuine denial control. See the
[Apache advisory](https://www.openwall.com/lists/oss-security/2022/02/11/3).

Other releases, ARM, TLS, custom prefixes, concurrent route edits, bind sessions,
nondefault Admin API key roles, and payloads requiring additional target runtimes remain outside these profiles.
The module's Unix catalogue also includes PHP/Python adapters; catalogue
compatibility alone does not prove those runtimes exist in a target image.

The [verification report](../VERIFICATION-20261119-apisix.md) records **33/0**
across these four profiles: 29 owner cases, four independent handler cases and
ten sessions used and closed. All 20 observed Docker resources are absent after
the replay. The restricted 2.12.0 bypass remains outside that qualification.
