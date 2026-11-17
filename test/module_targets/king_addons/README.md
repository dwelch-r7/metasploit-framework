# King Addons functional target

This lab runs the public module against genuine pinned WordPress, King Addons
and Elementor distributions. The [dated verification report](../VERIFICATION-20261117-king-addons.md) records
which profiles passed; a declaration alone does not establish qualification.

```sh
bundle exec ruby test/module_targets/king_addons/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb king_addons
```

Pass additional profile names to the same command to run them serially:

| Profile | Cases | Distinct behavior |
| --- | ---: | --- |
| king_addons | 6 | Check; PHP Meterpreter and Unix shell twice; AutoCheck disabled |
| king_addons_minimum | 3 | First affected 24.12.92; check and both session families |
| king_addons_subdirectory | 5 | Real /portal installation; both families twice |
| king_addons_plain | 5 | WordPress plain permalink nonce page; both families twice |
| king_addons_fixed | 3 | Fixed check, automatic refusal, forced Subscriber/upload denial |
| king_addons_missing_nonce | 5 | Valid control plus 404 and ordinary 200 pages through check/run |
| king_addons_registration_disabled | 2 | Public check and genuine disabled-registration rejection |
| king_addons_existing_admin | 3 | Existing administrator fallback with both session families |
| king_addons_existing_wrong_password | 2 | Existing account; wrong supplied password remains unrecorded |
| king_addons_existing_subscriber | 2 | Existing Subscriber authenticates; upload denied; credential saved |

Pinned official distributions 24.12.92, 51.1.14 and 51.1.35 use Elementor 3.21.0
and the shared WordPress 6.8.3 / PHP 8.3.28 / MariaDB 11.2.2 images. The official
51.1.35 ZIP and SVN tag have an internal PHP header/constant of 51.1.32 while
their readme identifies 51.1.35. The files remain intact and every vendor digest
is checked. The first affected SVN tag is unavailable, but its complete official
download and matching version labels are pinned.

The real Elementor canvas page uses the King Addons Login Register Form widget.
Its public localized registration nonce matches the widget's hidden nonce when
registration is enabled. The disabled-registration profile retains the genuine
localized nonce while the vendor omits the registration form. Plain URLs come
from get_permalink(), including the actual page ID. No nonce, response, role,
version label or vendor security check is fabricated or patched.

Before and after public calls, independent tests require original administrator
password authentication, upload and benign PHP/shell UID-33 execution. Anonymous
role override creates an administrator on affected releases, creates a Subscriber
on the fixed release, or receives the genuine disabled-registration response.
A token/ACK control separately verifies basic callback reachability. Existing
accounts are created through WordPress APIs during setup; native gates validate
their real passwords, cookies and access before module calls.

Successful public cases verify actual session types, UID-33 file execution,
password/administrator access, FileDropper file restoration, credential/service
origin and Successful login timestamps. Repeat cases require stable database
core/login/service IDs. An authenticated Subscriber retains its credential with
no inferred administrator access after upload failure. Missing nonce and invalid
password paths require no credential. No loot output is expected.

Owned account/plugin/session cleanup uses WordPress APIs. Existing fixture users
are retained; only bounded recent tokens with the exact case User-Agent are
removed. Selected original users/hashes/roles/tokens/usermeta, plugin options
including Elementor logs, pages/Elementor metadata, configuration and the entire
plugin file tree must restore. Other WordPress options, security transient rate
buckets, database auto-increment, service logs and free-space values are outside
that selected-state comparison. Complete database restoration is not claimed.

Use one serial guarded pipeline. Public stacks have at most three containers
with CPU, matching memory/swap and PID caps, init and loopback-published ports.
Native readiness used two containers. Containers and attached resources are
removed; unrelated images and volumes are not pruned. Failed runs and independent
controls are retained for diagnosis before any owner fix is accepted.

The initial unchanged-owner run opened four sessions but failed four reporting
assertions because no credentials were saved. The same five-case replay passed
after the focused reporting fix. Focused unit HTTP, payload and reporting doubles
verify contracts; the public tests establish real authentication and persistence.

Windows, other dependency/runtime versions, TLS, multisite, staged/dynamic PHP
transport and paid features require separate qualification. Inline PHP Meterpreter
with explicit stdapi and cmd/unix/reverse_bash are the declared payload paths.
