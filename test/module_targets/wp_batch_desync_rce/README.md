# WordPress batch desync RCE genuine targets

These opt-in labs reuse the pinned official core archives and capped WordPress,
MariaDB and reporting PostgreSQL services from [WP2Shell](../wp2shell/README.md).
The host console keeps the stack at three containers. Vendor files remain
unchanged. Native source/data and in-band SQL controls gate public module calls.
A bounded app-to-host TCP handshake establishes the callback route before any
payload is attempted; listener addresses are measured for the current machine.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/wp2shell/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wp_batch_desync_rce
```

Tests must prove PHP Meterpreter and command-shell session types, execution as
the native web user, credential/login/loot reporting, uploaded-plugin removal,
created-account cleanup and repeat execution. KeepAdmin has explicit operator
cleanup after its preservation assertion. Stateful cache/changeset posts are
recorded rather than claimed to be removed. Registration and independent native
RCE proofs do not count as accepted Framework module/session coverage. See the
campaign verification journal for actual qualified results and known failures.
