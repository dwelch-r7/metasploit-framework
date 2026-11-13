# OPC-UA detection lab

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb opcua
```

Dated verification reports establish actual qualification. The fixture uses
unchanged upstream open62541 1.5.10, commit
`93c3bdfc9ea4718b503c6cbf57876237addd0f2c`, built from its SHA-256-pinned release
archive and pinned Ubuntu 22.04 base. The Dockerfile is the complete recipe;
compilation uses two jobs. Ubuntu build/runtime package versions are recorded
in the image. A first build needs network access to Ubuntu and upstream sources.

Small source-available applications use the public SDK configuration and client
APIs. The native client independently discovers endpoints, opens real sessions
and reads the server's software version. The module itself only sends HEL and
reports ACK/ERR metadata. No module method or protocol response is replaced.

Server configurations advertise the native default buffer, a 16 KiB buffer, and
a deliberately insufficient 4 KiB buffer that generates a genuine ERR. Bounded
TCP forwarders preserve the actual HEL/response bytes: one splits the first
response byte from the rest, one does the same for ERR, and one closes after the
genuine eight-byte ACK header. The native SDK succeeds through fragmentation
and rejects truncation. These are explicit transport-fault cases. Python's
unchanged standard-library SMTP server supplies an unrelated-service control.

Nine functional cases cover those paths, refusal, repeated execution, exact
service metadata and database identities, workspace separation, and switching
between real ports. Passive capture reuses the existing qualified observer;
SQL queries and cgroup counters also reuse existing controls. Native controls
run before and after owning calls, including PID/birth and binary/package hashes.

Only three containers run: target 192 MiB/0.5 CPU/96 tasks, Framework
768 MiB/1.5 CPUs/256 tasks and reporting PostgreSQL 128 MiB/0.2 CPU/64 tasks.
Combined RAM/swap equals RAM; target ports publish only on loopback. The usual
runner removes the project's containers, network and disposable database state.
Licensed gateways, other SDKs, TLS-only transports and other platforms need
individual review and are not established by this plain OPC-UA TCP lab.
