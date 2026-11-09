# HTTP forward proxy detection

From the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb http_proxy
```

Digest-pinned Apache 2.4.62 runs genuine mod_proxy_http/mod_proxy_connect with
open and denied policies, plus an independent origin and unrelated HTTP server.
The origin serves real HTTP on port 8080 and HTTPS on ports 443 and 8443.
Certificates are generated inside the disposable image; no private keys are
committed. Native Ruby Net::HTTP uses its own proxy and TLS implementations to
check actual destination bytes through each allowed tunnel, verify refusals and
record certificate identity before invoking Framework. No proxy response is
simulated, and no Internet destination is contacted.

Twelve cases cover repeated GET forwarding, pattern/status negatives, denied
and unrelated servers, default and explicit CONNECT ports, HTTPS URI and bare
authority inputs, and unavailable destinations. CONNECT detection itself checks
only the status code; native HTTPS requests establish that the fixture's tunnel
actually works. These are different claims. Module HTTP traces retain the exact
request authority and real replies. No session or state-changing operation is
needed; repeated scans check reuse.

Only random loopback ports are published. Native commands, image identities,
responses, source hashes, exact counts and teardown are retained by the
[shared runner](../README.md). Registration alone is not qualification.
Authenticated proxies, upstream proxy chains, IPv6, TLS to the proxy itself,
multiport discovery and Framework database reporting remain separate work.
