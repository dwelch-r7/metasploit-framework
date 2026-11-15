# WordPress administrator plugin upload

These bounded profiles retain all 25 original examples for
`exploit/unix/webapp/wp_admin_shell_upload`. Each profile is a separate disposable
project: one actual WordPress installation, its database and Framework (three
services), or genuine unrelated Apache and Framework (two services). Run them
serially through the guarded runner, which checks the shared lock, empty global
container inventory and resolved service count before starting a project.

| Family | Selected examples | Count | Actual native target |
| --- | --- | ---: | --- |
| `wordpress_admin` | Root checks, finite PHP, shell, stageless Meterpreter and denied execution | 11 | Root WordPress |
| `wordpress_admin_prefix` | All prefix cases except staged Meterpreter | 8 | `/wordpress/` WordPress |
| `wordpress_admin_locked` | Administrator upload denial and denied execution | 2 | WordPress with `DISALLOW_FILE_MODS` |
| `wordpress_admin_unrelated` | Product identification and denied execution | 2 | Unrelated Apache |
| `wordpress_admin_staged` | Repeated root staged PHP Meterpreter | 1 | Root WordPress |
| `wordpress_admin_prefix_staged` | Repeated prefix staged PHP Meterpreter | 1 | `/wordpress/` WordPress |

**Registration and host collection checks do not qualify these new profiles.**
The staged profiles remain real, unqualified reproductions. Historical cold-state
seed 7721 runs encountered an invalid-session reconnect burst during the second
staged PHP Meterpreter bootstrap. No production session fix is claimed, and the
cause is not established as an upload-module defect. Keeping these cases in
separate profiles does not remove them from the 25-case coverage.

From the repository root, run one family at a time:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wordpress_admin
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wordpress_admin_prefix
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wordpress_admin_locked
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wordpress_admin_unrelated
```

The two known staged-session reproductions require a bounded external controller
and retained teardown evidence. To use the historical order, temporarily add
`--seed 7721` to `.rspec-local`, preserving its existing contents, then run one
staged family through the same guarded runner. Remove only that temporary option
afterward. Each selected example still performs both original executions; a
single staged example therefore attempts the same payload twice. Do not run the
two staged profiles together or interpret an interrupted run as a passing result.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wordpress_admin_staged
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wordpress_admin_prefix_staged
```

The [shared digest-pinned WordPress 6.8.3/PHP 8.3 recipe](../wordpress/README.md)
is unchanged. Root and `/wordpress/` installations permit administrator uploads.
The locked installation retains working administrator authentication while
WordPress's genuine policy denies plugin installation. Profiles use the original
separate database names and publish only random loopback HTTP ports; reverse
listeners remain on the internal Framework network. All services use `init` and
CPU, memory and PID limits. A WordPress project is capped at 0.5 CPU/512 MiB/128
PIDs for MariaDB, 0.5 CPU/384 MiB/128 PIDs for WordPress, and 1 CPU/1536 MiB/256
PIDs for Framework. Unrelated Apache uses 0.25 CPU/128 MiB/64 PIDs and the same
Framework cap. No additional capabilities are granted.

`profiles.rb` is the component-owned table used by both the native probe and
functional bridge. The bridge requires the original acceptance source and
selects exact example descriptions. It changes no example body or cleanup helper.
Manifests retain hashes for that source, the bridge, the table, native controls,
actual service recipes, payload sources and consumed helpers. Direct use of the
original acceptance file still collects all 25 cases; use the profile manifests
for bounded execution. The native probe defaults to the root scope, or accepts
an explicit `WORDPRESS_ADMIN_PROFILE` selected by each manifest.

For each selected WordPress service, native PHP independently inspects actual
roles/capabilities, installation paths, writable directories, filesystem method
and command execution as `www-data`. Independent HTTP controls establish profile
identity, valid/invalid credentials and administrator/limited-account upload
permissions. An independent RubyZip/Net::HTTP client installs and executes a
harmless proof plugin twice per upload-enabled installation, verifies the web
account and exact file proof, then removes it through WordPress's plugin API.
The locked profile proves actual upload denial instead. Each WordPress profile
also makes one real PHP callback into an internal standard Ruby TCP listener;
the unrelated profile checks the actual Apache marker and expects no PHP callback.
No module login, upload, ZIP or payload helper implements these native controls.

Every successful owner execution path runs twice. Sessions must create a fresh
file as the web account and remove uploaded plugins and package archives through
FileDropper. The finite PHP case explicitly consents to `AllowNoCleanup` and tests
operator cleanup separately. Failed-case recovery removes only artifacts created
after the native snapshot, after assertions have determined the result. Recovery
cannot turn a failed cleanup assertion into a pass.

Historical TLV observations narrow the staged investigation to bootstrap,
`core_loadlib` and packet transport, but lack session/socket labels. Later native
source/PHP checks passed; a passive socket sampler saw an inverse TCP tuple but
could not attribute it to an Apache PID because proc fd reads were denied. No
owner module ran in that native gate. Missing decoded replies or PID mappings do
not establish wire silence or a component cause. See the retained
[proxy and session history](../VERIFICATION-20261109-proxy-history.md) and
[deferred investigation](../DEFERRED.md).

Native commands, response captures, source hashes, exact counts and owned teardown
are retained according to the [shared guide](../README.md). No human module
Scenarios are generated. Other WordPress/PHP versions, operating systems, remote
filesystem methods, TLS, plugin activation and Framework database credential
persistence require separate qualification.
