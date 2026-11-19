# Kong Gateway Admin API execution

The maintained matrix passes **16/0** on the pinned stock 2.1.4 image: thirteen
positive and three plugin-disabled cases. Three owner sessions and two independent
handler sessions are used and closed. See the [verification record](../VERIFICATION-20261119-kong.md)
for exact scope, repairs, failed pilots and lifecycle evidence.

The lab uses genuine Kong routes, the bundled `pre-function` plugin and a private
PostgreSQL database. It exercises intentionally exposed administration, rather
than treating a release number as evidence of code execution. Kong's
[Admin API documentation](https://docs.konghq.com/2.1.x/admin-api/) describes
route/plugin administration; the release's
[dependency declaration](https://github.com/Kong/kong/blob/2.1.4/kong-2.1.4-0.rockspec)
identifies the external serverless-functions plugin. The tests record the actual
installed Lua source hashes, application version and database version.

From the Framework repository root:

```sh
MODULE_TARGET_NAMESPACE="kong-$$" bundle exec ruby tools/dev/run_guarded_module_target_tests.rb kong_gateway_214 kong_gateway_no_plugin
```

The guarded runner serializes profiles, discovers random loopback ports, keeps
native/console/HTTP evidence, and removes each stack before starting the next.
Kong is capped at 0.75 CPU and 512 MiB; its PostgreSQL database is capped at
0.25 CPU and 384 MiB. The positive session profile adds one private Framework
reporting database capped at 0.25 CPU and 384 MiB; the negative profile needs
only two services. Published ports bind loopback. Kong's disposable database uses
tmpfs. No package is installed in the stock application image. Framework's
console runs on the host using the repository's existing Ruby and gems.

`kong_gateway_214` enables the image's bundled plugins. `kong_gateway_no_plugin`
uses the same release with `KONG_PLUGINS=off`, so native plugin rejection provides
an independent negative control. The suite verifies native administration,
exact command bytes, repeats, actual owner calls and entity/file cleanup. A
native control failure withholds owner execution.

The native command control builds Lua from decimal bytes, independently of the
module's string representation. Quotes, dollars, Lua delimiters, Unicode and
physical newline/tab bytes are checked against real files owned by Kong's user.
Passive observation records the actual module methods, HTTP responses and socket
write buffers without replacing their behavior.

Kong's legacy `PUBLIC-API-RPORT` and `PUBLIC-API-RHOST` options contain hyphens.
Configure them with `set PUBLIC-API-RPORT <port>` and, when necessary,
`set PUBLIC-API-RHOST <host>`; Framework's inline `run VAR=value` and
`check VAR=value` grammar does not accept these names. The suite checks the stored
values before invoking the owner.

Real Bash and Netcat shell controls reuse the existing stock-target and session
helpers. Session cases must use the session,
match its persisted owner/payload/workspace row, close its connection/process,
and verify its database closure. The Netcat repeat shares the selected
module instance. The shared session verifier retains Kafka's delivery hooks;
changes to that helper require Kafka regression replay too.

The public compatible-payload catalog is captured before owner session tests.
Kong's existing Unix-labelled target rejects Linux fetch adapters. Separate
native handler diagnostics have used and closed x86/x64 inline and x64 staged
Meterpreter sessions on the stock image; those controls do not qualify these
unsupported Kong payload selections. No target metadata is changed for testing.

Other releases, macOS, authentication, TLS, prefix/proxy routing, other payloads,
concurrent changes and injected cleanup faults remain unqualified. Failed setups
and host-probe diagnostics are retained separately from the passing matrix.
