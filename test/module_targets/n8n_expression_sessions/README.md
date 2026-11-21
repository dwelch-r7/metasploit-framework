# n8n default wget/Meterpreter sessions

Run from the Framework root:

```sh
MODULE_TARGET_NAMESPACE=my-n8n-sessions bundle exec ruby tools/dev/run_guarded_module_target_tests.rb n8n_expression_sessions
```

This opt-in profile extends the pinned, unmodified n8n 1.120.0 image from
[`n8n_expression`](../n8n_expression/README.md). The only additional victim
mount is a read-only Node helper for callback, process/socket and file evidence.
A small PostgreSQL reporting service records real Framework session rows.
The console runs on the host; only two capped containers run at a time.
Host ports 4492 (callback) and 4493 (fetch) must be available.

The existing native owner/login, ordinary IIFE and unsafe-expression controls
must pass first. An independent TCP callback proves the route and UID. The
ordinary multi/handler then generates the same inline Linux x64 Meterpreter
fetch payload used by the exploit's default target, using wget. Its actual
encoded command runs through the victim's native Node `execSync`, without
changing that command. Only after that session can be used and closed does
the real owner run twice on one selection: first with normal target/payload
defaults and AutoCheck, then with AutoCheck disabled.

Assertions cover the fetched ELF bytes, UID 1000, PID plus birth time, socket
ownership, remote proof-file bytes, responsive n8n, original SQL session row
closure, process baseline restoration and no remaining listener/jobs/sessions.
Passive observations retain original command/request/response bytes. Two
foreign workflows must remain byte-for-byte equivalent through the API and
the global SQLite workflow IDs must match. Final native teardown requires
zero workflow/execution records and unchanged installed vendor hashes.

`FETCH_DELETE` retains its default `false`: the executable is expected to
remain after shutdown. The test records it before explicitly removing this
fixture artifact. It does not claim automatic executable cleanup. Docker
teardown runs on failures too; native-readiness failures withhold an owner
verdict. Windows and other payload families are outside this profile.
