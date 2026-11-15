# WPS Hide Login discovery

These profiles use genuine WordPress 6.8.3, PHP 8.3.28 and checksum-pinned official
WPS Hide Login releases 1.9 and 1.9.1. The common seed installs and activates the
real plugin through WordPress APIs and stores a known hidden login slug. No
application route or vulnerability response is replaced.

Run selected profiles serially from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb wps_hide_login wps_hide_login_prefix wps_hide_login_fixed wps_hide_login_fixed_prefix wps_hide_login_absent wps_hide_login_unrelated
```

Each application profile starts three capped containers: WordPress, MariaDB and
Framework. The unrelated Apache control starts two. The guarded runner removes
each complete stack before starting the next. WordPress uses 0.5 CPU/384 MiB/128
PIDs, MariaDB 0.5 CPU/512 MiB/128 PIDs, Framework one CPU/1536 MiB/256 PIDs and
Apache 0.25 CPU/128 MiB/128 PIDs; every service uses init. The shared WordPress and
HTTP components own base images, database credentials and build sources.

| Profile | Real target | Expected behavior |
| --- | --- | --- |
| `wps_hide_login` | 1.9 at `/`, slug `module-login-alpha` | Reveal the configured working login twice |
| `wps_hide_login_prefix` | 1.9 under `/wordpress`, slug `module-login-beta` | Reject the native `/404/` redirect |
| `wps_hide_login_fixed` | 1.9.1 at `/` | Refuse login discovery |
| `wps_hide_login_fixed_prefix` | 1.9.1 under `/wordpress` | Refuse login discovery |
| `wps_hide_login_absent` | Genuine WordPress without the plugin | Refuse login discovery |
| `wps_hide_login_unrelated` | Genuine Apache | Refuse login discovery |

Independent native controls inspect the installed core/plugin version, archive
checksum, activation, stored slug, prefix, actual source hashes and account.
Anonymous HTTP checks establish the real secret login form, hidden default login,
readme bytes and Referer/no-Referer redirects before invoking the owner. A reported
URL must match the configured slug and target authority and serve the real login
form. Accepting any HTTP 302 would incorrectly count the subdirectory's `/404/`
response as success. Version 1.9 has a literal `/wp-admin/options.php` exception;
its root and subdirectory behavior differ in the retained native captures.

The suite invokes the public scanner `run` interface. Root success and negative
profiles repeat twice, and root also covers a missing installation and a native
closed TCP port. Postflight compares plugin/configuration state and checks empty
Framework sessions/jobs, zero OOM events and zero PID-limit events. Ordinary
application audit logs remain. `memory.events:max` is informational.

The official archives are pinned in `releases.json`. Setup verifies their bytes
before extracting them and removes the temporary download. These are disposable
local targets. TLS, multisite, other core/plugin releases and PHP runtimes remain
separate coverage. Default CI excludes these acceptance examples. This guide
does not assert that an unrun or failing profile qualifies the owner; inspect
the actual result JSON and native evidence. No human module Scenarios are added.
