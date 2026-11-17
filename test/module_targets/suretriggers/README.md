# SureTriggers container targets

The unchanged module's six-case 1.0.82 baseline exposed incorrect `Untried`
credential reporting and a false account/loot claim for a rejected username.
Changing only the owner source made all six cases pass with genuine PHP
Meterpreter and Unix shell sessions. The final ten-profile matrix passes all 41
cases in one aggregate. See the [verification report](../VERIFICATION-20261117-suretriggers.md)
for source hashes, native evidence, preserved failures and qualification limits.

```sh
bundle exec ruby test/module_targets/suretriggers/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb suretriggers
```

Select profiles as needed. Passing several names runs them serially, with full
teardown between profiles. The default covers check, both session types twice,
reporting, cleanup and the real invalid-username response. Boundary/permission
profiles cover check, a normal blocked/denied run and actual endpoint denial with
AutoCheck disabled. Other positive profiles use one run of each session type.

| Profile | Plugin | Action | Target condition | Cases |
| --- | --- | --- | --- | ---: |
| `suretriggers` | 1.0.82 | 27007 | Root, unconfigured, repeated sessions | 6 |
| `suretriggers_empty` | 1.0.78 | 3102 | Empty bearer, repeated sessions | 6 |
| `suretriggers_empty_fixed` | 1.0.79 | 3102 | First fixed empty-bearer release | 3 |
| `suretriggers_configured` | 1.0.78 | 27007 | Existing key reset and restored exactly | 4 |
| `suretriggers_empty_configured` | 1.0.78 | 3102 | Configured key denies empty bearer | 3 |
| `suretriggers_reset_boundary` | 1.0.79 | 27007 | Reset remains vulnerable | 4 |
| `suretriggers_fixed` | 1.0.83 | 27007 | First fixed reset release | 3 |
| `suretriggers_plain` | 1.0.82 | 27007 | Plain REST fallback | 4 |
| `suretriggers_subdirectory` | 1.0.78 | 3102 | `/portal`, plain REST fallback | 4 |
| `suretriggers_no_check` | 1.0.82 | 27007 | AutoCheck disabled | 4 |

Actions are CVE-2025-3102 and CVE-2025-27007. A passive vulnerable-version result
on a configured 1.0.78 target does not prove the empty-bearer bypass works.

Official archives are fully hashed and use WordPress 6.8.3/PHP 8.3.28/MariaDB
11.2.2. Native gates use actual routes, authentication, roles, plugin upload and
benign PHP/shell UID 33 execution. No vendor security check or SaaS response is
fabricated. Credentials are checked through the real reporting database, including
login status/time and stable core/login identities on repeated execution.

The normal login timestamp and exact encrypted key storage are restored only
after ownership checks. Other options/logs/auto-increment/free space are outside
selected state restoration; complete database restoration is not claimed.

Run one guarded pipeline, max three capped containers, loopback ports only.
The explicit inline PHP Meterpreter/stdapi and cmd/unix/reverse_bash paths are the
qualified payloads. Automatic/default payload selection, Windows, staged/dynamic
PHP transport, existing-account collisions/updates, TLS, multisite, other runtimes
and authenticated fixed-release SaaS verification remain unqualified.
