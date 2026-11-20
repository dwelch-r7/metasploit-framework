# InvoiceShelf native targets

The fixture rebuilds the official InvoiceShelf 1.3.0 release archive on a pinned
PHP 8.3 CLI image. The historical `invoiceshelf/invoiceshelf:1.3.0` image tag is
unavailable. Release dependencies, frontend assets and Laravel sources remain
unchanged; `vendor.json` pins the archive and thirteen installed source files.
The application's own migrations/seeder and installation APIs initialize SQLite.

Run with Framework's bundle and Docker Compose v2 available:

```sh
MODULE_TARGET_NAMESPACE=invoiceshelf-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceshelf
MODULE_TARGET_NAMESPACE=invoiceshelf-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceshelf_file_sessions
MODULE_TARGET_NAMESPACE=invoiceshelf-local bundle exec ruby tools/dev/run_guarded_module_target_tests.rb invoiceshelf_named_cookie
```

The first profile tests the real version check, repeated Unix and PHP command
payloads, exact ASCII/Unicode/LF/CRLF/quoted bytes, key-file selection and native
wrong-key denial. Every owner command first passes independently through the real
Laravel serializer/encrypter and HTTP session chain. Physical proof bytes and UID
33 establish execution; HTTP 200 alone does not. Repeats retain the same selected
console object and disable AutoCheck. Before/after source, installer, database and
resource checks guard the runtime.

The file-session profile tests the 2.0 mitigation on the same 1.3.0 application:
real file-backed sessions must ignore the forged data cookie, and the module must
withhold execution. Its version-only check still returns Appears. The named-cookie
profile uses `APP_NAME=InvoiceShelf`, letting Laravel choose
`invoiceshelf_session`; native execution gates the owner test. A failure in that
profile must remain visible for investigation.

The session profiles `invoiceshelf_bash` and `invoiceshelf_php_shell` first use
and close an independent handler, then use and close two real owner sessions.
They verify public session file/identity APIs, exact proof ownership, actual
payload metadata, original reporting-row closure, live HTTP health and complete
PID/birth/socket baseline restoration. The Unix owner path selects target 1 and Bash explicitly, matching its native
handler control. Each family uses a
fresh stack to prevent failed handlers from contaminating later cases.

`invoiceshelf_php_staged` and `invoiceshelf_php_inline` retain independent native
Meterpreter readiness gates. A failed gate withholds owner execution and adds no
qualification. The first staged owner path, if readiness passes, omits TARGET and
PAYLOAD to exercise the PHP default. No private payload runtime patch is applied.

The app needs at most one container: 1 CPU, 768 MiB memory/equal swap, 128 PIDs,
loopback-only published HTTP, ephemeral storage and UID 33. The PHP test server
uses the application's own Laravel router and two workers; nginx/Apache behavior
is unqualified. Session profiles add the existing 0.2 CPU/128 MiB/64 PID ephemeral PostgreSQL
reporting service, for a maximum of two containers. Test credentials and the published default APP_KEY are disposable
fixture data.

The guarded runner serializes heavy phases, gives each stack a unique project and
ownership labels, and removes its containers, networks and ephemeral volumes in
ensure, including on test failure. Do not run `compose up` with a shared default
project or leave finished stacks running. Follow the repository's Docker lifecycle
instructions and preserve unrelated resources during routine cleanup.

See [the investigation report](../VERIFICATION-20261120-invoiceshelf.md) for exact
results, native session limits, repair evidence and retained failures. These
profiles do not establish compatibility with other releases, MySQL, TLS, alternate
cipher families, or every public payload.
