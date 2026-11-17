# WP GDPR Compliance targets

Complete pinned official 1.4.2/1.4.3 archives, real plugin activation, guest
settings requests, WordPress registration and native mail/password/login proof.
All 22 public cases pass in four serial profiles; see the
[verification report](../VERIFICATION-20261117-gdpr-compliance.md). Registration
text alone is not privilege proof. The owner retains accounts and configuration
changes; test recovery is a separate guarded native operation. PHP delivers mail only to a local spool.

```sh
bundle exec ruby test/module_targets/gdpr_compliance/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  gdpr_compliance gdpr_compliance_fixed gdpr_compliance_subdirectory \
  gdpr_compliance_plain
```

| Profile | Condition | Qualified cases |
| --- | --- | ---: |
| `gdpr_compliance` | 1.4.2, repeat, optional administration email, username boundaries, collisions and route failures | 13 |
| `gdpr_compliance_fixed` | 1.4.3, closed registration and independently proved subscriber outcome | 3 |
| `gdpr_compliance_subdirectory` | 1.4.2 under `/portal` | 3 |
| `gdpr_compliance_plain` | 1.4.2 with actual plain permalinks | 3 |

The runtime pins WordPress 6.8.3, PHP 8.3.28 and MariaDB 11.2.2. Complete vendor
archives and installed-file hashes are checked. An ordinary PostgreSQL reporting
role starts with an empty schema which Framework creates itself. Native controls
run before and after public calls. Local sendmail delivery captures the genuine
WordPress messages; tests follow each actual reset link and form before checking
password, cookie, role/capabilities and user-management HTTP access.

The owner has no AutoCheck and may retain option changes even when registration
fails. On the fixed release, HTTP 200 from the old settings action does not change
the options. If registration was already enabled, an ordinary subscriber may
still be created; that is not administrator access. Tests distinguish these
states and recover only accounts, named options and captured mail owned by the
run. A login-page TARGETURI is an invalid base URL; native gates separately
exercise missing/incorrect nonces at the real AJAX endpoint.

One capped stack runs at a time, with at most three containers. No external mail
delivery, other runtime releases, TLS, multisite or broader SQL/RCE claim is made.
