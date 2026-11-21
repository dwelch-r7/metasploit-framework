# Calibre normal Linux fetch Meterpreter target

```sh
MODULE_TARGET_NAMESPACE=calibre-fetch-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb calibre_fetch
```

This companion shares the [Python profile's](../calibre_python/README.md) genuine
Calibre target, native formatter/callback gates, reporting and full session
lifecycle assertions. The actual console chooses
`cmd/linux/http/x64/meterpreter/reverse_tcp` after selecting Linux TARGET 1.
The first owner invocation therefore omits PAYLOAD; its repeat explicitly
selects that observed default on the same console object.

The stock fetch payload must first work independently. Its configured listener
binds to all host interfaces while advertising the address proved by a real
target callback. Target PID/birth, physical UID-1000 session proof, original
reporting row, fetch artifact removal and complete process/socket restoration
are required. The HTTP fetch listener uses port 4493 and the reverse handler
uses 4492, under the shared guarded-runner lock.

At most two capped containers run, with loopback-only published ports. Ensure
cleanup removes both and their ephemeral network immediately, including on
failure. This qualifies the stated Linux default path only; global Windows
TARGET 0 and other releases need independent testing.
