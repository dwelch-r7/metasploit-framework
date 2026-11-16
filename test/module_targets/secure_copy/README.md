# Secure Copy Content Protection genuine targets

These opt-in profiles use unmodified official 2.8.1 / 2.8.2 archives on pinned
WordPress 6.8.3 / PHP 8.3.28, MariaDB 11.2.2 and ordinary-role PostgreSQL 16.
`releases.json` pins complete ZIPs and every installed archive file, including
uppercase `README.txt`. The entire human module guide and Scenarios are preserved.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/secure_copy/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb secure_copy secure_copy_subdirectory secure_copy_prefix secure_copy_populated secure_copy_count2 secure_copy_fixed secure_copy_inactive secure_copy_absent
```

Run serially. Each project has three capped containers: app 1 CPU / 512 MiB,
MariaDB 0.5 CPU / 512 MiB and PostgreSQL 0.25 CPU / 384 MiB. Swap equals memory,
PIDs are limited to 128, init is enabled and published ports bind loopback.
The reporting service reuses the Elasticsearch PostgreSQL component without
starting Elasticsearch. All stack objects are removed after each profile.

Twenty cases cover public checks and runs, repeat reporting, a subdirectory,
custom table prefix, empty/populated vendor reports, USER_COUNT=2, fixed and
inactive/absent prerequisites, reserved closed ports and fixed AutoCheck disabled.
Full target-generated password hashes must match genuine credential rows; all
source, user and vendor-table snapshots must remain unchanged by module calls.
These cases use no HTTP, SQL, credential-reporting or target-protocol doubles.

Normal vendor activation installs its tables and default subscription, then
exits through its redirect hook. A fresh PHP process verifies that state and
adds the native subscription shortcode through WordPress's post API. The
populated profile submits that real public form once. PHP remote streams are
disabled in this owned lab to suppress the form's optional external IP-geolocation
lookup; vendor source is unchanged. Mail delivery is disabled and integrations
retain vendor defaults. Other external integration behavior is unqualified.

Independent true/false UNION controls must recover a complete known hash only
on the affected enabled source. Bounded sleep controls separately confirm the
module's time-based path before/after public execution. Each profile starts with
a fresh non-superuser reporting schema and an isolated host console. Positive
runs use SqliDelay=0.6 and USER_COUNT=1 unless the count profile requests two.
Only profiles needing longer extraction opt into the runner's bounded timeout.
Do not reduce the delay to hide an error or accept a partial hash.

Exact results, failures and qualification limits belong in the campaign journal.
Profiles are registered setup until their actual runtime evidence is accepted.
