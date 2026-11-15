# POST SMTP password reset disclosure

These disposable profiles use genuine WordPress 6.8.3/PHP 8.3.28, MariaDB and
Exim, with checksum-pinned official POST SMTP 2.8.6, 2.8.7 and 2.8.8 archives.
The affected boundary is through 2.8.7; 2.8.8 rejects unauthenticated device
registration. No HTTP routes, plugin authentication or mail responses are
replaced. Archives stay in the ignored source cache, outside Git.

From the repository root, prepare sources and run profiles serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/post_smtp/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb post_smtp post_smtp_287 post_smtp_prefix post_smtp_fixed post_smtp_no_logs post_smtp_absent post_smtp_unrelated
```

| Profile | Real configuration | Expected result |
| --- | --- | --- |
| `post_smtp` | 2.8.6, root | Check; valid reset URL and exact email loot, repeat with/without AutoCheck; missing user |
| `post_smtp_287` | 2.8.7, root | Same success and failure paths at the last affected release |
| `post_smtp_prefix` | 2.8.7, `/wordpress` | Same paths under a real subdirectory installation |
| `post_smtp_fixed` | 2.8.8 | Safe check; AutoCheck refusal; registration rejection with AutoCheck disabled |
| `post_smtp_no_logs` | 2.8.7, plugin logging disabled | Real SMTP delivery; clear missing-log failure on both runs |
| `post_smtp_absent` | WordPress without the plugin | Negative checks and automatic execution refusal |
| `post_smtp_unrelated` | Genuine Apache | Negative checks and automatic execution refusal |

Setup requires Docker Compose with [`!reset` support](https://docs.docker.com/reference/compose-file/merge/#reset-value).
A normal profile uses three containers: WordPress (0.5 CPU/384 MiB/128 PIDs),
MariaDB (0.5 CPU/512 MiB/128 PIDs) and Exim (0.25 CPU/128 MiB/64 PIDs). Absence
uses two and unrelated Apache uses one (0.25 CPU/128 MiB/128 PIDs). All use init.
Framework runs in the host's existing bundle with an isolated configuration and
metadata cache. `nice` reduces its host scheduling priority; its memory and
processes are outside the target cgroups. Each stack is removed before the next.
Only WordPress's random loopback HTTP port is published. Database and SMTP share
an internal network; SMTP cannot relay mail outside the fixture.

Native prerequisites inspect installed versions, archive/source hashes, the
real account and configuration. They request a legitimate reset, receive and
parse the actual Exim mailbox, validate the key through WordPress core, and
compare unauthenticated plugin API behavior. These gates run before the module.
Successful module runs must print the correct fresh URL, match the delivered
mail and actual database log, validate the key with core, and store exactly the
independently retrieved email page as loot. Console exit zero alone proves none
of these outcomes. Repeats use fresh module instances and check state each time.

Registration on affected targets overwrites the mobile-device map and server
URL, and requesting a reset changes the account activation key. The module
cannot recover unknown previous settings. The fixture explicitly restores its
owned baseline after each stateful run, verifies password/configuration equality
and invalidates the generated key; application mail/audit logs remain until
stack teardown. This operator action is recorded separately from module
cleanup. No account password is actually changed.

Postflight records target OOM/PID-limit counters and checks empty Framework
sessions/jobs. Default CI excludes the functional examples. These profiles do
not cover TLS, multisite, an existing mobile QR authorization nonce, other PHP
runtimes or every plugin release. They do not add human module Scenarios or
claim qualification without a complete passing result and cleanup receipt.
