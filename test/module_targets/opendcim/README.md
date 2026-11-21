# openDCIM SQL injection and command execution

```sh
MODULE_TARGET_NAMESPACE=my-dcim-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb opendcim
```

This opt-in profile uses the pinned official `24.01-beta` image, whose installed
version is **24.01**, and a pinned MariaDB **10.11.9** image. No application source is
patched. Apache supplies `REMOTE_USER=dcim`, matching the deployment mode in the
module documentation; this profile does not qualify HTTP Basic Auth or LDAP auth.
The original container installer creates the real database. Its completed 302
response is expected; the health probe follows the local redirect and checks the
application page. The native observer records responses without following redirects.

Only two capped services run: the application and its database. The database uses
ephemeral tmpfs. The host runs Framework. A read-only PHP CLI helper outside the
document root uses the existing PDO runtime for independent database/file evidence.

Native prerequisites include real SVG rendering, a stacked SQL request that
creates a proof row, and exact quoted/Unicode/CRLF command execution through the
real report endpoint. Seven installed source fingerprints, the actual installer,
and all configuration rows are observed. Non-empty LDAP values are seeded to
make accidental changes visible; both those values and unrelated settings must
survive each public module operation. Original factory settings are restored
afterward, with no extra backup/proof tables.

The six examples cover native readiness, the original timed check, a natively
refused connection, repeated plain and quoted commands, and a calibrated `/dcim/`
base path. Every exact command first runs through an independent parameterized
configuration setter and the real report endpoint, then its proof is removed
before actual module delivery. A repeat uses the same selected module. Passive
traces retain original SQL, request, response and command bytes without stubs.

This profile uses `cmd/unix/generic` for physical command proof. Reverse sessions,
the dropper target/architectures, authentication variants, other releases and
patched-release behavior remain unqualified. A registration or a container health
result alone does not prove the owner passes. Native-control failures withhold
the corresponding module verdict. All containers and ephemeral resources are
removed on success, failure or interruption.
