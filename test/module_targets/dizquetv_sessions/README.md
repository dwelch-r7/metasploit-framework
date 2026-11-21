# dizqueTV Bash reverse sessions

```sh
MODULE_TARGET_NAMESPACE=my-dizquetv-sessions bundle exec ruby tools/dev/run_guarded_module_target_tests.rb dizquetv_sessions
```

This opt-in profile extends the [pinned 1.5.3 command fixture](../dizquetv/README.md)
without changing the application or installing packages. Only two capped services
run: the application at 384 MiB / 0.7 CPU, and a temporary reporting PostgreSQL
service at 128 MiB / 0.2 CPU. Both use equal memory/swap caps; the guarded runner
namespaces and removes all containers, ephemeral networks and database state.

Four examples require native command/state readiness and an acknowledged UID-0
callback, then a stock Bash payload through a real handler, an independent real
API session, and two original module sessions on the same selection. Native
failure withholds the owning verdict. The independent API request stays pending
for its foreground shell; settings restore through a separate connection while
that shell is live. The module's original five-second trigger timeout and ensure
restoration run without replacement.

Public session APIs create UID-0 proof bytes and request graceful shell exit.
Independent stock Perl/procfs observations match PID/start time and socket inode,
then require complete process and callback-socket recovery. The original database
session row must close, and Framework jobs/sessions must empty. All nine root
JSON stores and unrelated non-default settings preserve while sessions are live
and afterward; original factory settings restore at the end. The health probe
requests only the static page. Proof and native payload files are deliberately
removed by the fixture and their absence verified.

The first owner run observes the default Linux target with explicit Bash payload
and empty COMMAND. The repeat explicitly selects target 0, disables AutoCheck
and reuses the same module instance. This does not qualify default fetch delivery,
Windows, other payload families or other releases. Ordinary unit CI excludes
these Docker tests; registration alone does not establish a passing result.
