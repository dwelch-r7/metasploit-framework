# Node.js legacy V8 debugger

```sh
MODULE_TARGET_NAMESPACE=my-nodejs-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb nodejs_v8
```

One official Node 7.10.1 Alpine image is pinned by its registry manifest digest,
with `linux/amd64`, UID1000, 128 MiB RAM/swap, 0.5 CPU and 64 PIDs. Only the
debugger is published, on a random loopback port. No package installs, daemon
privileges or host Docker socket are required. The runner names and labels the
project and removes its container/network on all exits.

The ordinary program keeps its event loop active with a timer and writes one
foreign sentinel. The real Node binary supplies the entire V8 debugger service.
This explicitly covers active-program behavior; it does not claim the idle REPL
timing noted in the module's existing documentation. Health checks inspect the
listening socket without occupying the debugger's single-client connection.

An independent Python stdlib client parses the real legacy header/JSON protocol.
It verifies Node identity, plain and quoted Unicode/CRLF file writes and UID,
an invalid-expression negative, unchanged process/file state and a separate
native UID1000 callback before the owner is allowed to run. No existing project
dependency supplies a Python client for this legacy protocol; the client uses
the standard email-header, socket and JSON libraries.

Stock TCP and TLS Node payloads must first pass native syntax and real-session
controls. Sessions are used after the real post-bootstrap session-open event.
The original owning module then runs each family twice on one selection. Remote
file bytes/UID, PID/birth, callback closure, graceful shell exit and empty Framework
sessions/jobs are checked. After remote shell exit, Framework closes its peer;
native Node wrappers must then exit and active/half-closed callback sockets must
disappear. Module/check observations
are passive and preserve original source behavior. No reporting database is
claimed for this profile. Full program/process and foreign-file preservation
stays separate from session success; refused-port checking retains the reason-
bearing CheckCode requirement.

Registration is not a passing verdict; consult the
[dated verification report](../VERIFICATION-20261121-nodejs-v8.md)
and raw results. Default payload selection, bind payload, idle REPL timing,
other Node releases, Windows and macOS remain separate coverage work.

The image is `node:7.10.1-alpine` at
`sha256:4954ce53247180e207772f936223b11d52a7e4ee712dfe73fe2a75e39f785067`.
See the existing [module documentation](../../../documentation/modules/exploit/multi/misc/nodejs_v8_debugger.md)
and [Node 7.10.1 debugger documentation](https://nodejs.org/download/release/v7.10.1/docs/api/debugger.html).
