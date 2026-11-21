# Lucee authenticated scheduling acceptance target

```sh
MODULE_TARGET_NAMESPACE=lucee-scheduled-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb lucee_scheduled
```

This profile shares the official, pinned [5.3.7.43 target](../lucee/README.md).
Normal CFAdmin configuration sets a lab web-admin password. Real HTTP login
must succeed independently before the Framework owner is invoked. A genuine
scheduler control fetches a standalone CFML source from WEBrick, publishes its
exact physical bytes, executes it through Tomcat and deletes the native task
and file. The source server accepts the actual scheduler's `RequestTimeout`
query parameter through the standard HTTP library.

The real Unix command target uses `cmd/unix/generic`, that admin password and
the normal `AllowNoCleanup=true` option required for a sessionless command.
ASCII and combined quoting/Unicode/multiline cases each repeat on the same
selected object after independent Bash and CFML controls. Physical command
bytes, exact downloaded CFML source, actual task deletion and payload-listener
closure are checked. Without a session, fixture cleanup removes the remaining
CFML files; FileDropper session cleanup is unqualified.

A final wrong-password case must stop before task creation or server startup.
It runs last because this real release briefly delays further logins after a
bad password. Each profile starts with a fresh container. The target remains
unchanged vendor code; no auth/HTTP implementation is replaced.

Only one application container runs: 1 CPU, 768 MiB memory/equal swap, 128 PIDs
and a loopback-only published port. Use an explicit namespace and the guarded
runner's shared lock; remove finished stacks immediately in ensure cleanup.
Windows, sessions and other releases remain separate qualification work.
