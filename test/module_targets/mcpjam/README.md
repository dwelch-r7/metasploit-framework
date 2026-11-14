# MCPJam Inspector native targets

These profiles use pinned official Linux amd64 images, the original npm startup,
and a real installed MCP SDK. No application route or production module method is
replaced. No model/provider account is required.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb mcpjam mcpjam_loopback_143 mcpjam_loopback_146 mcpjam_token
```

| Profile | Version | Original default | Functional cases |
| --- | --- | --- | ---: |
| `mcpjam` | 1.4.2 | Network reachable, unauthenticated | 11 |
| `mcpjam_loopback_143` | 1.4.3 | Binds loopback | 5 |
| `mcpjam_loopback_146` | 1.4.6 | Binds loopback | 5 |
| `mcpjam_token` | 1.5.0 | Docker bind, session-token authentication | 5 |

The positive suite covers checks, ASCII/Unicode commands, Unicode server IDs,
output/quiet tool modes, direct shell delivery, real Node command shells and
Linux x64 HTTP-fetch Meterpreter sessions. Each case repeats from the same console module configuration; Framework uses
its normal execution replicants. Public session APIs write exact markers; independent target observations
verify bytes, UID, process identities, registry restoration and fetch-file removal.
Remote session exit and Framework transport closure are measured separately.
Native controls establish version/bundle identity, real SDK execution and an
unrelated connection that module attempts must preserve.

The boundary profiles retain the vendor binding/authentication defaults.
Independent local controls prove the application works before actual remote
checks, AutoCheck guards, forced tool/direct attempts and disabled-AutoCheck paths.
A genuine localhost administrative token is used only by native controls and is
never supplied to the unauthenticated owner. Loopback refusal is inconclusive
remote detection and does not establish a patched API.

Each serial profile uses three capped services: Inspector 512 MiB / 0.75 CPU /
192 PIDs, Framework 768 MiB / one CPU / 256 PIDs, and PostgreSQL 128 MiB / 0.2 CPU /
64 PIDs. The internal network exposes no host ports. The common guard requires
an empty inventory, bounds service count, and tears down each project.
Image digests and installed bundle hashes live in [vendor.json](vendor.json).

Results, confirmed fixes, earlier harness failures and limits are recorded in the
[verification report](../VERIFICATION-20261114-mcpjam.md). Other versions,
TLS/proxy deployments, architectures, payload families and concurrent server-ID
ownership changes require separate evidence. Later vendor versions intentionally
replace existing IDs; this suite does not prevent an accepted replacement or claim
ownership of a connection whose response was lost.
