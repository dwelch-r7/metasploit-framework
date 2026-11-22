# Redis replication bundled-extension qualification

Run from the repository root:

```sh
MODULE_TARGET_NAMESPACE=my-redis-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb redis_replication
```

The target is a pinned official Redis 5.0.14 x64/glibc image. The existing bundled
extension requires glibc; the dynamically compiled CUSTOM path has separate
compiler/ABI and writable-build prerequisites and is not qualified here.
No target password is configured in this isolated lab.

Native `redis-cli` first proves server/configuration identity and directly
loads the original extension. Quoted Unicode/CRLF commands must create exact
UID-999 files twice, followed by native module unload and verified removal.
A stock handler/native extension control then gates owning execution. Both use
the documented staged `linux/x64/meterpreter/reverse_tcp` family, keeping inline
Bourne delivery short. An earlier large-single-payload pilot was intentionally
stopped during transfer; its controls and cleanup are retained without an
owning-completion verdict.

The owning cases check the real service and attempt two x64 Meterpreter runs.
Public session APIs and physical PID/birth/file/shutdown checks gate success.
Post-run state is compared with the native baseline before a second attempt;
failures retain actual state rather than silently repairing it. This draft is
not a qualification until the functional receipt passes.

Only the capped target and Framework containers run. Both are namespaced and
immediately removed with their ephemeral network and volume, including on failure.
