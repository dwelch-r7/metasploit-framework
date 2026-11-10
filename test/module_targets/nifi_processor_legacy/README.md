# Genuine NiFi ExecuteProcess legacy target

Run `bundle exec ruby tools/dev/run_module_target_tests.rb nifi_processor_legacy` from the repository root.

This profile uses the stock pinned NiFi image, public fixture account and native
HTTP client. One release per profile retains the existing readiness bound.
The bounded corpus requires real
commands and sessions twice, plus preserved stopped GetHTTP credentials.
The module retains its default five-second DELAY; native stop/delete latency
is recorded separately and does not establish payload startup time.
Windows branches are unqualified by these Linux fixtures.

All paths use exact component-graph checks around every case and repeat.
Native controls create a real stopped GetHTTP processor with a real Basic
credential, require its authenticated response, and replay it after the suite.
Cleanup failures retain the dirty graph before any explicitly labelled native
operator restoration of emitted owned UUIDs. Test proof files are fixture-owned.

The modern vulnerable profile requires exact bearer-token datastore and HTTP
Authorization receipts through the public `run -o BEARER-TOKEN=value` route.
An invalid bearer must be refused even when valid fallback credentials exist.
The Linux Fetch adapter is rejected as incompatible with the Unix target; that
case requires no session and an unchanged graph. Fetch delivery and Windows
execution remain unqualified. Self-signed local TLS is exercised with certificate
verification disabled; trusted TLS is not claimed. No responses, sessions or
credentials are simulated.

A passive standard Framework event subscriber identifies the actual execution
replicant for failure diagnostics. It retains only that module reference,
intercepts no request or response, and does not change callback timing. Any
operator restoration is limited to its actual newly created component UUIDs.
