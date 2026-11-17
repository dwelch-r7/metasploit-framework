# Pie Register functional target

Unmodified official 3.7.1.4, 3.7.1.5 and 3.7.1.6 distributions run on pinned
WordPress 6.8.3 / PHP 8.3.28 / MariaDB 11.2.2. The numeric user-ID bypass used by
`exploit/unix/webapp/wp_pie_register_bypass_rce` is fixed in 3.7.1.5. That release
still has a separate username bypass; 3.7.1.6 moves social authentication behind
the optional addon. No addon is installed in these targets.

```sh
bundle exec ruby test/module_targets/pie_register/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  pie_register pie_register_subdirectory pie_register_plain \
  pie_register_fixed pie_register_fixed_latest
```

The app, ordinary MariaDB account and separate nonsuperuser PostgreSQL reporting
database have explicit CPU, matching memory/swap and PID caps. Only loopback
ports are published. Use the guarded serial runner to limit work to one stack,
at most three containers, and remove attached containers/volumes/networks.
Unrelated images and volumes are not pruned.

Independent controls verify exact vendor sources, real password login, WordPress
cookie validation, administrator permissions, genuine plugin upload, benign
PHP/shell execution and callback reachability before and after the public owner.
The selected patched releases must reject the numeric bypass even though their
normal authenticated upload still works. The different username path is checked
separately to avoid treating 3.7.1.5 as universally fixed.

Public cases use explicit PHP Meterpreter with embedded stdapi and the PHP
command-shell payload. They require typed sessions and independent UID-33 file
proof, reporting, repeat execution and FileDropper cleanup of the actual plugin.
The owner creates authentication sessions on existing accounts; test-owned
cleanup removes only fixture sessions with the exact expected user agent,
bounded count and recent timestamps. Both tokens created by a login are handled.

| Profile | Cases | Purpose |
| --- | ---: | --- |
| `pie_register` | 9 | Check, both session families twice, no AutoCheck, subscriber/nonexistent/zero IDs |
| `pie_register_subdirectory` | 5 | Both session families twice below `/portal` |
| `pie_register_plain` | 5 | Both session families twice with plain permalinks |
| `pie_register_fixed` | 3 | 3.7.1.5 numeric-path check, automatic and forced refusal |
| `pie_register_fixed_latest` | 3 | 3.7.1.6 numeric-path check, automatic and forced refusal |

Selected original users/hashes/roles/session tokens/user metadata, main plugin
options, pages, plugin-table rows and vendor/plugin entries are compared after
cleanup. Other WordPress options, usage counters, auto-increment state and
filesystem free-space metrics are outside those comparisons. Complete database
restoration is not claimed. Repeats reuse the console selection; Framework makes
distinct internal exploit clones. The actual cached encoded PHP payload is read
from the session's run object without generating new bytes. This owner's custom
ZIP uses those bytes directly, without an additional PHP wrapper.

The installed staged/dynamic-extension PHP transport remains separately
unqualified. Other runtime versions, Windows PHP, TLS, multisite, alternate
content layouts and social addons remain untested. Declared cases do not prove
qualification: actual results belong to dated verification records. The human
guide's historical Scenarios are preserved.
