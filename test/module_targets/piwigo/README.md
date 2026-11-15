# Piwigo credential disclosure

These serial targets exercise `auxiliary/gather/piwigo_cve_2023_26876` against
unmodified official Piwigo archives. The lab uses a digest-pinned PHP 7.3.11 /
Apache runtime from the existing WordPress image; its WordPress entrypoint is
replaced and no WordPress application is installed or served. MariaDB stores
the target accounts. A separate PostgreSQL instance receives real Framework
credential records through the host console.

Prepare sources and run one profile at a time from the repository root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby test/module_targets/piwigo/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb piwigo
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb piwigo_prefix
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb piwigo_13_4
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb piwigo_13_6
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb piwigo_fixed
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb piwigo_empty
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb piwigo_unrelated
```

| Profile | Genuine target | Purpose |
| --- | --- | --- |
| `piwigo` | 13.5.0 | Populated gallery and real credential persistence |
| `piwigo_prefix` | 13.5.0 under `/gallery/` | Subdirectory requests |
| `piwigo_13_4` | 13.4.0 | Earlier affected release |
| `piwigo_13_6` | 13.6.0 | Last affected stable release |
| `piwigo_fixed` | 13.7.0 | Fixed input validation with working ordinary history |
| `piwigo_empty` | 13.5.0 without albums/photos | Empty welcome page and login-page version fallback |
| `piwigo_unrelated` | Static Apache marker | Unrelated-product refusal |

All seven profiles pass 37 functional cases and 65 public calls. The
[qualification record](../VERIFICATION-20261115-piwigo.md) separates native controls,
original defects, harness corrections and final results. The original module
printed correct hashes while saving usernames in the hash field; the repaired
module must preserve exact real PostgreSQL values.

The ordinary web installer creates the schema. Authenticated vendor APIs create
the album, source-generated PNG photo and member accounts. Before any module
action, native CLI reads verify exact release/source hashes and actual account
rows; independent HTTP verifies valid/rejected login, administrator history,
literal SQL disclosure, exact row bytes and denied member access. The fixed
control requires legitimate history access before testing input rejection.

Accounts include comma/semicolon and Unicode usernames and the default NULL
guest password. MariaDB's session `group_concat_max_len` is 96 bytes. Native SQL
proves the complete account collection exceeds that value and the old aggregate
would truncate. Independent scalar HTTP queries must disclose each complete row.
Functional success requires PostgreSQL to contain exactly the nonempty target
hashes, associated usernames, hash formats and correct service/module origin.
Repeated runs must preserve the same credential set. NULL passwords are not
invented hashes. Wrong credentials, nonadministrator access, missing paths,
fixed releases and unrelated products must save no credentials.

The target account/hash/status snapshots must remain unchanged after collection.
This covers those fields rather than the complete database; normal session and
audit activity is retained until teardown. Source archives and extracted files
are verified before and after testing. Framework configuration and reporting
data start fresh per profile; each example uses a fresh reporting workspace.

Each Piwigo stack has three containers: app 0.5 CPU / 384 MiB / 128 PIDs,
MariaDB 0.5 CPU / 512 MiB / 128 PIDs, PostgreSQL 0.5 CPU / 256 MiB / 128 PIDs.
The unrelated control has two. All use init and before/after OOM/PID checks.
HTTP and reporting PostgreSQL have random loopback ports; MariaDB stays internal.
The host Framework process runs outside target cgroup limits.

The guarded launcher refuses existing containers and a held global pipeline lock,
then removes its project containers/networks/volumes on success or failure.
No proprietary image, outbound newsletter subscription or external SMTP account
is needed. The [release catalog](releases.json) pins official archives and the
relevant source hashes; [13.7 release notes](https://piwigo.org/release-13.7.0)
identify the history input-validation fix. Source inspection places introduction
in 13.2.0; 13.2/13.3 and customized database table prefixes remain untested here.
