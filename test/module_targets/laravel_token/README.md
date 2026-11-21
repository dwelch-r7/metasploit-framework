# Laravel token deserialization target

Run with Framework's bundle and Docker Compose v2:

```sh
MODULE_TARGET_NAMESPACE=laravel-token-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb laravel_token
```

The image uses the pinned PHP 7.4.15/Apache runtime already used by the Ignition
fixture, removes its application, and installs genuine Laravel 5.6.29 from a
locked dependency tree. The starter application is pinned to revision
`3f92cf66f53b3b53467497acc0d2a00cbd7b65f0`. It adds the documented POST route
needed to reach the real CSRF middleware. No vendor source is patched.
Seventeen application/dependency source hashes pin the relevant installed code.

Composer 2.2.26 resolves the committed lock. The image installs that lock with
Composer 1.10.27 because this Laravel release expects its older package-metadata
layout. Both Composer downloads and the starter archive have checked SHA256
values. The first Composer-2 bootstrap failure is retained separately.

Native controls serialize the installed classes and use the installed Laravel
Encrypter. Generation must leave the proof absent. The actual HTTP middleware
must then create exact bytes as UID 33 and return a standalone output marker.
Faker 1.9.2 deliberately blocks gadget 1 during wakeup: its debug response
reflects the command marker while leaving the proof absent. Gadgets 2, 3 and 4
must independently execute. A reflected substring alone is insufficient proof.

The profile exercises the real check, exact ASCII/Unicode/LF/CRLF/quoted command
bytes, explicit and discovered keys, repeated selection, wrong-key denial and
short-key rejection. Non-session payloads try all four fallbacks; three can
execute in this pinned dependency tree. Append-only proof checks expose that
multiplicity instead of hiding it through file overwrites. Controls must pass
before an owner verdict is admitted; failed prerequisites withhold that verdict.
Default session payloads and genuine fixed releases need separate qualification.
Human Scenarios remain separate from these automated observations.

Only one application container runs: 1 CPU, 512 MiB memory/equal swap and
128 PIDs. HTTP is published only on loopback. Run stacks serially through the
guarded runner, with an explicit task namespace and the shared heavy-work lock.
Ensure cleanup removes the finished container and ephemeral network after
success, failure or interruption. Never retain an unused finished stack.
