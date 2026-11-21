# Calibre content-server native acceptance target

```sh
MODULE_TARGET_NAMESPACE=calibre-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb calibre
```

The Dockerfile installs the official Linux amd64 **7.14.0** binary on pinned
Ubuntu 22.04 and checks its vendor-published SHA-512. It runs headlessly as UID
1000, using the normal `calibredb` and `calibre-server` tools. No installed
Calibre source or HTTP transport is patched. The server uses its normal
unauthenticated configuration; write access is not enabled.

Startup seeds one genuine empty-format book. This prerequisite matters: the
vulnerable list endpoint evaluates a template for each matching book. An empty
library cannot establish successful remote template execution. Before and after
tests, the actual binary version, bundled Python, UID, book identity and four
installed function fingerprints must match the committed capture.

Independent Python controls build the JSON RPC array with the standard JSON
encoder and the template's command literal with `repr`. Generation must leave
the proof absent. Local `SafeFormat` evaluation and the real `/cdb/cmd/list`
endpoint must separately create exact physical file bytes as UID 1000. Each
proof is removed and its absence checked before another attempt. These controls
gate the Framework owner rather than treating its failed request as setup proof.

The profile exercises the real check and Linux command target (TARGET 1), using
`cmd/unix/generic`. It covers ASCII, single/double quotes, Unicode, literal LF
and combined CRLF/quoting/metacharacters. Each working owner case repeats on the
same selected console object. Trace events retain the real encoded command,
request and response bytes without replacing module behavior. The
[verification report](../VERIFICATION-20261121-calibre.md) records the source
repair, failed baseline, native prerequisites and qualified limits. These
automated observations do not supply human Scenarios.

Only one application container runs: 1 CPU, 768 MiB memory/equal swap and
128 PIDs. HTTP publishes only on loopback. Run stacks serially with an explicit
task namespace and the guarded runner's shared heavy-work lock. Ensure cleanup
removes finished containers and ephemeral networks after success, failure or
interruption. Windows, other releases, default session payloads and raw
backslash commands excluded by the owner's metadata need separate qualification.
