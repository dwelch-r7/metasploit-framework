# Redis protocol and credential consumers

```sh
MODULE_TARGET_NAMESPACE=my-redis-protocol-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb redis_protocol_ascii redis_protocol_utf8
```

These two serial profiles use the same pinned official Ubuntu Redis 6.0.11
package and limits as the [Lua profiles](../redis_lua/README.md): one UID 101
service, 128 MiB RAM/swap, 0.5 CPU, 64 PIDs, read-only root, bounded tmpfs and
random loopback publication. The runner labels/names each project and removes
it on all exits. No package installation, extra project dependency or host
Docker socket is needed.

| Profile | Synthetic lab password |
|---|---|
| `redis_protocol_ascii` | `module-target-redis-password` |
| `redis_protocol_utf8` | `päss☃word` |

Independent native gates establish the actual package, binary/library hashes,
correct/incorrect authentication, real shell/Lua operation, original daemon
identity and complete configuration. Native Redis commands seed and verify
Unicode keys, NUL/CRLF data, trailing whitespace, empty strings and list/set/
sorted-set/hash values. A real native SAVE to a Unicode filename must work
before the owning upload module is allowed to run. Only names absent before
the fixture are removed afterward; the foreign file and original keys remain.

The five original consumers run through their real entry points:

- `auxiliary/scanner/redis/redis_server`: INFO/PING with ordinary console
  credentials and explicitly typed UTF-8 Ruby/API datastore credentials.
- `auxiliary/scanner/redis/redis_login`: real successful/incorrect result
  statuses and successful recovery on one selected module.
- `auxiliary/gather/redis_extractor`: exact returned scalar/structured values,
  real CSV loot, empty/trailing/binary data and a second run.
- `auxiliary/scanner/redis/file_upload`: actual RDB bytes/UID, two Unicode
  filenames, same-selection repetition and restoration of all keys/config.
- `exploit/linux/redis/redis_debian_sandbox_escape`: two genuine id-based checks
  with typed UTF-8 credentials. Owning session delivery remains covered by the
  separate Lua profiles.

Console parsing can produce binary strings, which already count UTF-8 bytes
correctly. Explicit UTF-8 datastore assignment represents supported Ruby/API
callers and keeps that distinction observable; it does not replace any module
method. Passive tracing records original packet bytes, argument encodings,
data-reader returns, authentication replies and reporting calls. Database
persistence of services or credentials is not claimed by these profiles.

Stock redis-cli request captures are unit fixtures only. Their collector sends
canned ACKs to observe the client's original request bytes; no module interacts
with this collector. Actual-service authentication, raw response captures,
data, physical uploads and every module verdict use the real Redis server.
See the official [RESP specification](https://redis.io/docs/latest/develop/reference/protocol-spec/)
for binary bulk-string lengths and framing.

Registration is not a passing verdict. The
[dated verification](../VERIFICATION-20261121-redis-protocol.md) retains original
failures, separate assertion/probe faults, source comparisons and current results.
Malformed/fragmented response handling, large data, limits, TLS, nondefault ACL
users, extra releases/platforms and reporting databases remain further work.
