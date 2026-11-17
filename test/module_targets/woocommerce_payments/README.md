# WooCommerce Payments administrator creation

These targets use unmodified official 5.6.1 (affected) and 5.6.2 (fixed)
plugin distributions on pinned WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2.
The main WooCommerce plugin is deliberately absent. The native authentication
filter, REST identity, permission checks and real administrator creation/login
are checked independently before Framework runs.

Prepare the checksum-pinned archives with the existing Framework bundle:

```sh
bundle exec ruby test/module_targets/woocommerce_payments/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb woocommerce_payments
```

Additional profiles are `woocommerce_payments_fixed`, `woocommerce_payments_plain`,
`woocommerce_payments_subdirectory`, `woocommerce_payments_inactive`, and
`woocommerce_payments_absent`. Pass selected names to the same guarded launcher;
it executes stacks serially. Each stack contains the app, its private ordinary
MariaDB database, and an isolated PostgreSQL reporting database. Only loopback
ports are published. App/database/reporting caps are 1/0.5/0.25 CPU and
512/512/384 MiB, with matching swap limits and 128 PIDs each.

The public check and run use a fresh Framework configuration and reporting
workspaces. Successful runs must create a real administrator, persist the exact
password credential and successful login provenance, and authenticate to the
real admin users page. The test removes only its named disposable accounts via
WordPress, then compares the original user hashes, roles and user metadata.
This is test-owned cleanup; the owner module retains accounts by design.
Generated password/email, plus-address email, explicit/no AutoCheck, repeated
use of the selected module with the same username after cleanup, nonadmin/missing identities, duplicate usernames
and a closed port are bounded base-profile cases. Native controls also run
afterward. Fixed/inactive/absent targets prove refusal independently. An inactive
affected plugin can still receive a version-based Appears check; runtime
permission refusal is evaluated separately.

Artifacts retain console output, exact source/archive hashes, native HTTP
requests/responses, account state, SQL reporting rows and resource counters.
The runner removes containers and attached volumes/networks even on failure.
No scenario output is added to the human-maintained module guide.
