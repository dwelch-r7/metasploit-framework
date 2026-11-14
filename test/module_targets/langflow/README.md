# Langflow MCP collection

The upstream Linux amd64 Langflow 1.8.4 image is pinned by digest in
[vendor.json](vendor.json). It runs its real Python 3.12 backend, SQLite database
and MCP SDK 1.26.0. No replacement endpoints or external AI providers are used.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb langflow langflow_empty langflow_auth
```

| Family | Auto-login | Privately owned canary flows | Anonymous SSE |
| --- | --- | --- | --- |
| `langflow` | Enabled | Two, including Unicode and a long description | Exposes MCP information |
| `langflow_empty` | Enabled | None | Returns an empty tool list |
| `langflow_auth` | Disabled | Two | Requires authentication |

All profiles keep `LANGFLOW_SKIP_AUTH_AUTO_LOGIN=false`. Native REST requests
without credentials must receive 403. In the exposed profiles, a credential-less
MCP client nevertheless initializes a session and lists the owned private flows.
The authenticated profile must reject anonymous SSE and accept a valid login
token for the same real MCP operations. A denied request alone is insufficient
to establish a working protected target.

The vendor's default auto-login startup creates 32 unowned starter flows. They
are real application data, and do not appear in the global tool list. The native
helper creates the two owned, private canaries through the authenticated API,
with `mcp_enabled=false`. The 1.8.4 global MCP listing still exposes these owned
flows. Cleanup deletes only those canaries and verifies the original flow IDs.

Native verification checks installed package/source hashes, application identity,
authorization, the complete MCP responses and unchanged flow registry. It uses
the vendor SDK's public request API with the same protocol version as the owner.
Raw REST bytes, gzip headers, decoded JSON and command exit statuses are saved.
The long canary description exceeds one 4,096-byte read; no mock response is used.

The console cases compare complete JSON loot and database rows, run twice on the
same selected module with distinct real MCP session IDs, and exercise missing
paths and refused connections. The test runner records inputs and removes the
whole project. There are three containers: target 3,072 MiB/one CPU, Framework
768 MiB/one CPU and reporting database 128 MiB/0.2 CPU. Swap equals memory limits,
ports bind only to localhost, and there are no application volumes to retain.

Scope: these Langflow 1.8.4 configurations and the MCP gathering owner. Other
Langflow versions, TLS, URL prefixes and the related RCE modules require their
own qualification. Native calibration successes are distinct from Framework
functional qualification; record the latter in a dated verification report.
