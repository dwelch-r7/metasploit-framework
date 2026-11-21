# Deferred TorchServe default Java session investigation

This diagnostic is unqualified and excluded from automatic registration. To
reproduce it in a disposable worktree, temporarily enable its preserved manifest:

```sh
manifest=test/module_targets/torchserve_sessions/manifest.yml
test ! -e "$manifest" || exit 1
cp test/module_targets/torchserve_sessions/manifest.deferred.yml "$manifest"
trap 'rm -f "$manifest"' EXIT HUP INT TERM
MODULE_TARGET_NAMESPACE=torchserve-session-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb torchserve_sessions
```

This profile extends the [pinned 0.8.1 target](../torchserve_check/README.md).
It first runs the genuine Java/YAML/MAR controls. A native callback and the
installed Perl observer establish the actual UID, PID birth and owning socket
inodes. The reporting database is disposable; session checks use original SQL
rows and public Meterpreter proof/shutdown APIs.

Three independent stock-payload controls gate owner execution. The first directly
executes a real generated Java JAR. The second serves that JAR's unmodified
payload class and configuration with Python's standard HTTP server, then invokes
it through an ordinary JDK URLClassLoader. The third independently registers a
native MAR using the repository's existing factory class and that standard HTTP
source, exercising the genuine TorchServe JVM context. All retain `Spawn=2`
setting and require exact physical UID-1000 proof, process/socket exit and
reporting-row closure. The supplied Java source is only a reflective native
launcher; it does not implement the payload, handler or vulnerable application.

The owner case omits TARGET/PAYLOAD for the first execution, observes actual
default selection, and repeats on the same selected console object. The original
MAR generator and served response bytes are traced passively. Physical MAR bytes
must equal the actual generator output. A remaining archive is recorded before
explicit fixture recovery; these checks do not claim automatic artifact cleanup.

The initial attempt's stock JAR works but its owner produces no session. That
failed frame is retained as `torchserve-session-original-no-callback-20261121T073629`.
Its whole profile remains failed. A second frame proves direct HTTP loading but
its owner still fails, despite matching payload class and configuration bytes.
The third frame finishes **4 examples / 1 failure / 1 pending**: both stock
controls pass, native MAR registration produces no session, and the owner is
correctly withheld. It uses the real application JVM, the existing factory class,
identical stock payload/configuration bytes and a standard HTTP source. This
prevents assigning the earlier owner failures specifically to its HTTP producer.
The application-context cause remains unresolved. This recipe remains under
investigation until native MAR readiness and a complete owner replay pass.

Five stock sessions across the three frames write exact UID-1000 proof, match
original reporting rows and close with public shutdown. The whole frames remain
failed; these partial results add no qualified module/profile/case totals. All
three stacks and their native HTTP sources are removed. Neither the normal
owner repeat nor embedded Java or shell delivery is qualified.

Run serially with an explicit namespace. At most two containers run together:
the application at 1 CPU/1536 MiB/equal swap/256 PIDs and the reporting database
at 0.2 CPU/128 MiB/equal swap/64 PIDs. Host native HTTP sources have explicit
process cleanup. The runner removes finished and failed stacks and ephemeral
networks immediately. Embedded (`Spawn=0`) Java, shell payloads and other
deployments require distinct native and lifecycle controls.
