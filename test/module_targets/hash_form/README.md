# Hash Form container targets

The check repair has a source-only public before/after reproduction: the original
normal 1.1.4 cohort fails all four cases; changing only the owner among 112 inputs
makes all four pass. All 37 cases in nine profiles pass in one aggregate; see the
[verification report](../VERIFICATION-20261117-hash-form.md).

```sh
bundle exec ruby test/module_targets/hash_form/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb hash_form
```

Profiles run serially with teardown between them. The default runs nine cases:
check, two sessions each of PHP Meterpreter with embedded stdapi, Unix reverse
Bash and HTTP-fetched Linux x64 Meterpreter, plus genuine 404/nonce failures.

| Profile | Plugin | Backend / condition | Qualified cases |
| --- | --- | --- | ---: |
| `hash_form` | 1.1.0 | Apache, repeats and 404 negatives | 9 |
| `hash_form_reintroduced` | 1.1.4 | Apache, normal AutoCheck | 4 |
| `hash_form_reintroduced_last` | 1.1.5 | PHP server, uploaded PHP executes | 4 |
| `hash_form_apache_upload_guard` | 1.1.5 | Apache serves literal PHP, no session | 2 |
| `hash_form_php_boundary` | 1.1.6 | Exact PHP path denied, ordinary XHR works | 3 |
| `hash_form_fixed` | 1.1.9 | Later PHP denial, ordinary XHR works | 3 |
| `hash_form_plain` | 1.1.0 | Plain permalinks | 4 |
| `hash_form_subdirectory` | 1.1.0 | `/portal` | 4 |
| `hash_form_no_check` | 1.1.0 | AutoCheck disabled | 4 |

`hash_form_reintroduced_force` is a separate four-case diagnostic used on the
original owner: public check returns Safe, yet all three forced session families
work. It is retained as a regression aid and is outside the selected 37-case
matrix above. A passive Appears is conditional on server execution of uploads.

The targets use pinned official archives and WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2,
plus an ordinary PostgreSQL reporting role. Linux/amd64 is explicit for the fetched
x64 path. One stack uses at most three CPU/memory/swap/PID/init-capped containers,
1.75 CPUs/1,408 MiB in total, and loopback ports only. The PHP server uses the same
official image's real CLI server under UID 33 with four bounded workers. It leaves
the genuine vendor `.htaccess` files intact; it does not implement Apache rules.

Native form/field APIs create a real form; preview HTML supplies its actual nonce
and extension list. Ordinary XHR uploads, missing/wrong nonces, wrong-delete
nonce, size/extension behavior and native encrypted-path Delete are verified.
Before/after controls also verify source catalogs, form/field/entry tables,
options, users, config, complete upload trees, callback and curl fetch routes,
and zero OOM/PID counters. First-upload directory initialization is recorded
separately from selected-state restoration. Vendor source and responses are not
patched or fabricated.

The owner retains PHP uploads. Tests capture actual file bytes/ownership and the
actual cached payload, perform native-verified UID 33 session operations, request
graceful remote shutdown, and remove only owned files through the genuine Delete
API. PHP-path bytes equal the actual cached encoded payload; command wrappers
are captured without regenerating them. Linux fetch binaries and processes must
disappear. This explicit operator recovery is separate from module cleanup.

Preserved prerequisite failures matter: 1.1.1 ordinary GIF upload raises vendor
`explode(array)` TypeError; 1.1.4 executes PHP despite an advertised fixed-version
expectation; 1.1.5 Apache serves source despite an execution expectation. 1.1.6/.9
remove multipart fallback and allow non-dangerous TXT outside the requested GIF
list. Their selected PHP path is denied, including a vendor argument TypeError;
no whole-plugin security claim is made. All original attempts remain retained.

Unrelated WordPress options/logs/counters, whole-database restoration, Windows,
default/staged/dynamic PHP, other plugin/runtime releases, TLS, multisite and
other upload/server configurations are unqualified. Historical human Scenarios
remain unchanged.
