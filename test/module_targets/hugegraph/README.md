# Apache HugeGraph Gremlin execution

Digest-pinned upstream `hugegraph/hugegraph` images run their real Java 11
server and Gremlin engine. No HTTP emulator or replacement owner is used.

| Family | Version | Backend | Context | Authentication |
| --- | --- | --- | --- | --- |
| `hugegraph` | 1.0.0 | RocksDB | `/` | Disabled |
| `hugegraph_prefix` | 1.2.0 | Memory | `/hugegraph/` | Disabled |
| `hugegraph_open_130` | 1.3.0 | Memory | `/` | Disabled |
| `hugegraph_auth_130` | 1.3.0 | Memory | `/` | ConfigAuthenticator |

Run serially from the Framework root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb hugegraph hugegraph_prefix hugegraph_open_130 hugegraph_auth_130
```

Each family uses three containers: a target capped at 1 GiB/one CPU,
Framework at 768 MiB/one CPU, and PostgreSQL at 128 MiB/0.2 CPU. Only
localhost ephemeral target ports are published. The upstream image declares
an anonymous application volume; the runner removes it with the project.

The entrypoint uses vendor-supported backend, context and authentication
settings, runs vendor RocksDB initialization where applicable, and starts
the vendor server with its Java security manager enabled. Its 64 MiB minimum
free-memory protection remains enabled. A real Gremlin query determines
readiness, since REST starts before the Gremlin backend. ConfigAuthenticator
has no AuthManager RPC service, so the authenticated standalone profile uses
the supported empty `rpc.server_host` setting. The matching authentication
handler and auth graph factory activate the vendor private-action filters.

The independent native controls check version/product identity, arithmetic,
an empty graph, unchanged vendor JARs, sandbox denial, and the CVE bypass.
The native bypass restores the worker name in `finally`. Raw HTTP bytes,
gzip headers, decoded bodies and command exits are retained. The authenticated
control must accept normal authenticated queries, reject unauthenticated
queries, and block both execution paths without creating proof files.

The owner tests use real public console calls, repeat executions, compare
Gremlin worker identities/names, verify exact command bytes, and exercise
Bash and fetched Linux shell/Meterpreter sessions with remote proof, graceful
shutdown and database lifecycle checks. A controlled Bash execute-permission
fault proves worker restoration after a genuine ProcessBuilder launch failure;
the original mode and file hash must be restored before the next call. Qualification results and limitations
must be recorded in a dated verification report before counting these labs.

Version 1.3.0 alone does not establish protection: the unauthenticated pinned
image still permits the bypass. Apache's advisory requires Java 11 and
authentication alongside the upgrade. Sources:
[Apache advisory](https://openwall.com/lists/oss-security/2024/04/22/3),
[security guidance](https://hugegraph.apache.org/docs/guides/security/),
[authentication configuration](https://hugegraph.apache.org/docs/config/config-authentication/).

Limits: Linux amd64 containers and these four configurations; other versions,
distributed RPC, StandardAuthenticator and additional graph backends remain
unverified. The image runs as root, matching the module's privileged metadata.
