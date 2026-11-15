# BookingPress credential gathering lab

These profiles install official, checksum-pinned BookingPress 1.0.10 and 1.0.11
archives into genuine WordPress 5.2.4 / PHP 7.3.11 with MariaDB. The
[disclosure](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357/)
and the official release sources identify the unauthenticated
`bookingpress_front_get_category_services` injection and its 1.0.11 fix. No
plugin or SQL injection reply is replaced.

Prepare source archives, then select one profile from the Framework root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby test/module_targets/bookingpress/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb bookingpress
```

Additional profiles cover `bookingpress_prefix`, `bookingpress_table_prefix`,
`bookingpress_plain`, `bookingpress_low_limit`, `bookingpress_fixed`, `bookingpress_absent` and
`bookingpress_unrelated`. All normal deployments have a real category, service
and published `[bookingpress_form]` page. The plain profile uses WordPress's
ordinary page-ID query URL. The custom database prefix is `bp_`.
The low-limit profile sets MariaDB's real `group_concat_max_len` to 96 bytes;
native per-user queries must still retrieve every complete credential.

Before owner calls, native HTTP requests verify the ordinary category/service
lookup, rejection of an invalid nonce, an independent UNION scalar and exact
database user/email/hash values. The fixed release must refuse the same
injection while ordinary booking still works. Target state is read independently
through WordPress and compared before and after owner execution. Public console
check/run calls use real PostgreSQL reporting, and tests compare complete saved
credential hashes, addresses, service identity and printed email values with the
native database snapshot. Repeated calls use the same selected module instance
within each example. Negative paths must save no credentials.

One serial stack has at most three containers: app 0.5 CPU / 384 MiB / 128 PIDs,
MariaDB 0.5 CPU / 512 MiB / 128 PIDs and PostgreSQL 0.5 CPU / 256 MiB / 128 PIDs.
Memory-plus-swap limits equal memory limits. The console runs locally using the
existing bundle, avoiding a fourth container. Ports bind random loopback ports;
accounts and databases are disposable. The guarded launcher removes project
containers, networks and volumes after success or failure.

Runtime qualification is pending. The preserved human module guide and Scenarios
are unchanged. Other plugin/core/PHP releases remain outside this fixture's scope.
Original module defects and fixture corrections are recorded in the
[investigation record](../VERIFICATION-20261115-bookingpress.md).
