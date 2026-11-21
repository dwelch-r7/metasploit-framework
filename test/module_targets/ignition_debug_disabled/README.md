# Ignition debug-disabled control

This profile extends the [pinned native fixture](../ignition/README.md) with
`APP_DEBUG=false`, retaining the same application/vendor sources and PHP runtime.

```sh
MODULE_TARGET_NAMESPACE=ignition-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ignition_debug_disabled
```

The native control first proves that its genuine PHAR executes through PHP's
CLI as UID 33 and creates the exact file bytes. The gadget then raises its known
post-execution `LazyOption` return-type exception; that exit status alone is not
a readiness result. After removing the proof, the same archive must receive
HTTP 404 through the real application without executing. This repeats twice.

Only after native readiness and denial pass does the real owner run twice with
normal AutoCheck and ForceExploit disabled. Safe results must withhold its
exploit/PHAR methods, preserve proof absence and retain the selected console
object. Source inventories and real HTTP health bracket the profile.

The runner starts one capped app container and immediately removes it and its
ephemeral network, including on failure. The base fixture documents resource
limits, ownership and unqualified deployment/payload families.
