# Simple File List container targets

These opt-in profiles run the public `wp_simple_file_list_rce` module against
unmodified official 4.2.2 and 4.2.3 archives. All 17 cases in five profiles pass in one aggregate; see the
[verification report](../VERIFICATION-20261117-simple-file-list.md). Native
prerequisite probes independently established ordinary ZIP upload, rename,
download/delete, wrong-token/direct-PHP rejection, benign UID33 PHP execution on
4.2.2, and the actual extension veto on 4.2.3. Both recover ordinary operations.

```sh
bundle exec ruby test/module_targets/simple_file_list/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb simple_file_list
```

| Profile | Plugin / condition | Qualified cases |
| --- | --- | ---: |
| `simple_file_list` | 4.2.2, check and each explicit session payload twice | 5 |
| `simple_file_list_fixed` | 4.2.3, check, automatic block, real forced rename veto | 3 |
| `simple_file_list_plain` | 4.2.2, plain permalinks | 3 |
| `simple_file_list_subdirectory` | 4.2.2, `/portal` | 3 |
| `simple_file_list_no_check` | 4.2.2, AutoCheck disabled | 3 |

Profiles run serially with teardown. Each uses at most three capped containers:
WordPress6.8.3/PHP8.3.28, MariaDB11.2.2 and an ordinary PostgreSQL reporting role.
The caps total 1.75 CPUs/1,408 MiB per stack. Only loopback ports are published. Full archive hashes are checked on installation;
110 immutable installed files stay checked throughout. Two vendor log files are
recorded separately because the genuine engines append PHP deprecation/errors.
Notification mail alone is disabled through the ordinary plugin configuration.

Native gates before/after public calls use real shortcode tokens, file operations,
execution or denial, a callback token/ACK, selected state and zero OOM/PID limits.
Tests inspect the real reporting database and use actual typed sessions to create
a UID33 marker. They check physical FileDropper cleanup before a normal shortcode
view refreshes the plugin's file index. A forced fixed-release attempt retains its
PNG; tests record and remove that owned file through the genuine vendor endpoint.
Logs, `eeSFL-Log`, unrelated options and whole-database restoration are excluded.

Explicit `php/meterpreter_reverse_tcp` with embedded `stdapi` and `php/reverse_php`
are qualified in these profiles. Default/staged/dynamic PHP transport, other plugin/runtime releases,
TLS, multisite, custom upload paths and other security configurations are unqualified.
