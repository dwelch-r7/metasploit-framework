# WordPress core WP2Shell genuine targets

These opt-in targets use unmodified official WordPress 6.9.4/6.9.5 and 7.0.1/7.0.2
archives on the pinned PHP 8.3.28 / Apache base and MariaDB 11.2.2. Complete archives
and every installed vendor file are pinned. Core files replace the base image's
core only in a fresh disposable web volume; the upstream entrypoint generates
its usual database configuration. The ordinary native installer creates real
users and a published post. No plugins or persistent object cache are enabled.
The human module guides and Scenarios remain unchanged.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/wp2shell/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wp2shell
```

Run serially with one stack: app 1 CPU / 512 MiB, MariaDB 0.5 CPU / 512 MiB,
PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory, PIDs are capped at 128 and init
is enabled. Published ports bind loopback. PostgreSQL supplies a fresh ordinary
Framework reporting schema; the host console has an isolated configuration.
Teardown removes attached objects. External HTTP and mail integrations are
blocked by owned lab configuration and remain unqualified.

Independent native boolean, timing and full in-band data controls distinguish
both affected/fixed branch pairs. Public profiles verify their own source,
configuration, users/posts, genuine data/reporting/loot and resource state.
Complete blind extraction takes several minutes; normal positive tests request
one user with SqliDelay=0.6, with separate explicit count boundaries.
No target protocol, HTTP, SQL or reporting methods are replaced.

Registration and native controls are not proof that a Framework module passes.
Accepted public results belong in the campaign verification journal. The full
RCE cache/administrator chain, both session target families and their cleanup
need separate genuine qualification; the source catalog alone establishes none
of those outcomes.
