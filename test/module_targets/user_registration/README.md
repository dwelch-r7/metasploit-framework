# User Registration & Membership functional target

This component prepares unmodified official 4.1.1 and fixed 4.1.2 distributions
on pinned WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2. Vendor onboarding
creates the real subscriber plan, membership form and plugin login. All PHP
bootstrap APIs run as the web worker so upload directories have the real owner.

```sh
bundle exec ruby test/module_targets/user_registration/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  user_registration user_registration_subdirectory \
  user_registration_core_login user_registration_fixed
```

The three services are the app, its ordinary MariaDB database and isolated
PostgreSQL reporting database. Only loopback ports are published; CPU, matching
memory/swap and PID caps are explicit. The guarded runner serializes work and
removes containers and attached resources.

Native controls use vendor registration, role handling, password login and a
benign plugin upload/execute before and after the public owner. The generic
bounded Docker commands, callbacks, cgroup collection and reporting queries
are reused from the existing WordPress batch-chain helper. Its core SQLi gates
are replaced; no core SQLi probe runs in this component.

Public cases check the release, open typed PHP/Unix sessions, verify execution
as UID33 and exact reporting/loot, and repeat after FileDropper and test-owned
account/order/subscription cleanup. Repeats reuse the selected console module;
Framework creates a separate internal exploit clone for each execution. Native
password login and administrator-page access independently validate each account.
The reporting database must contain the exact credential and endpoint, a
Successful login and an attempt timestamp, without duplicate core/login rows.
The created account deliberately remains the module's side effect until the test
removes it; FileDropper itself removes the uploaded plugin.

| Profile | Cases | Purpose |
| --- | ---: | --- |
| `user_registration` | 7 | Affected 4.1.1, both session families twice, no AutoCheck and duplicate username |
| `user_registration_subdirectory` | 5 | Both session families twice below `/portal` |
| `user_registration_core_login` | 5 | Both session families twice with native core WordPress login enabled |
| `user_registration_fixed` | 2 | Fixed 4.1.2, Safe check and automatic exploitation refusal |

PHP cases explicitly use `php/meterpreter_reverse_tcp` and `EXTENSIONS=stdapi`.
They retain the actual run's cached encoded bytes after the session opens,
without regenerating the payload. With the installed payloads 2.0.257, the
separate no-extension single PHP diagnostic loses its sessions despite passing
native setup controls. Its original failure is retained; embedded extension
success does not qualify that path or the separately deferred staged payload.
No module default or payload dependency is changed to hide the failure.

Only the selected official Free releases are installed. The
[WPScan advisory](https://wpscan.com/vulnerability/2c0f62a1-9510-4f90-a297-17634e6c8b75/)
and vendor source identify Free 4.1.2 and Pro 5.1.2 as fixed. Commercial Pro,
Windows command execution, other core/PHP releases, TLS, multisite, disabled or
renamed membership forms and plain permalinks remain unqualified. The module
expects the published membership form and login routes created by onboarding.
The human guide's Scenarios are preserved. Dated verification records distinguish
actual results from these declared cases; registration alone proves no behavior.
