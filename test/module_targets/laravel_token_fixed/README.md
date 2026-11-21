# Laravel token genuine fixed-release control

```sh
MODULE_TARGET_NAMESPACE=laravel-token-fixed-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb laravel_token_fixed
```

This profile shares the pinned PHP runtime, starter application and Dockerfile
with the vulnerable target. Its separate committed dependency lock changes only
`laravel/framework` from 5.6.29 to genuine **5.6.30**; the other 85 packages remain
identical. Composer 1 installs the lock in the metadata format required by this
application. No vendor code is patched. Seventeen installed source hashes and
the package identity must match before and after testing.

The [upstream security release](https://laravel.com/docs/5.6/upgrade#upgrade-5.6.30)
changes token deserialization. A native control first serializes installed gadget
classes and encrypts them with the installed Laravel Encrypter. Generation must
leave the proof absent. Local default decryption then deserializes the object
and must execute exact command bytes as UID 33. After removing that proof, the
**same token** is sent through the genuine HTTP middleware and must leave the
proof absent. This separates a working gadget and encryption key from HTTP
denial by the fixed consumer.

The actual Framework check must return reason-bearing Detected without claiming
execution. Repeated owner commands must attempt all four fallbacks without
creating their physical proofs. Native positives precede each owner invocation.
The target's normal configuration uses a known lab APP_KEY and genuine debug
mode; a nonvulnerable result is not inferred from a changed banner or failed key.

One application container runs: 1 CPU, 512 MiB memory/equal swap and 128 PIDs.
HTTP binds only to loopback. Use the guarded runner with an explicit namespace
and run stacks serially. Ensure cleanup removes the container and ephemeral
network after success, failure or interruption. Failed native prerequisites
withhold owner verdicts. These automated observations do not supply human
Scenarios or qualify the 5.5 branch and other releases.
