# Simple Backup file disclosure

This target exercises `auxiliary/scanner/http/wp_simple_backup_file_read` against
genuine Simple Backup 2.7.10 and 2.7.11, using the existing pinned WordPress 5.2.4 /
PHP 7.3.11 image, bootstrap, database and archive helper. Vendor source is unchanged.
The [release catalog](releases.json) pins the official ZIPs and download-handler
source hashes. An owned local backup directory and ordinary backup file model
the download prerequisite; they are fixture setup, not a vendor-code repair.

Prepare archives and run each stack individually from the repository root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby test/module_targets/simple_backup/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb simple_backup
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb simple_backup_prefix
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb simple_backup_fixed
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb simple_backup_absent
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb simple_backup_unrelated
```

| Profile | Genuine target | Expected behavior |
| --- | --- | --- |
| `simple_backup` | 2.7.10 at `/` | Appears; exact traversal reads and ordinary backup reads |
| `simple_backup_prefix` | 2.7.10 at `/wordpress` | Same behavior with a subdirectory installation |
| `simple_backup_fixed` | 2.7.11 | Safe; traversal refused; ordinary depth-zero backup reads work |
| `simple_backup_absent` | WordPress without this plugin | Unknown; administrative endpoint redirects to login; no loot |
| `simple_backup_unrelated` | Static Apache marker | Unknown; no loot |

Native CLI inspection as the web user verifies actual versions, plugin activity,
archive/handler hashes, account fingerprints and readable fixture bytes. Raw HTTP
must establish the selected file contracts before any owner action. An ordinary
depth-zero backup read also runs on the patched target, so a generally broken
download endpoint cannot pass its fixed control. Successful confined reads on
2.7.11 are ordinary functionality, not traversal exploitation.

Affected cases cover repeated system/binary/configuration/backup reads, Unicode
and quoted filenames, relative paths, empty/missing files, insufficient depth and
rewritten nonexistent URL prefixes. Each expected read requires exactly one fresh loot file
with the actual target length and SHA-256. The operator controls `DEPTH`; both
deployments use 6 to reach the filesystem root. The configuration file is one
level above the backup directory, and ordinary backup reads use depth 0.

The first native probe incorrectly expected quoted-path refusal. Actual 2.7.10
HTTP returns the exact quoted file; that failed expectation is sealed and the
case becomes a positive control. No Framework module ran during that probe.
An original module test also incorrectly expected a nonexistent URL prefix to
prevent reads. Actual access logs show that exact prefix was requested and a
file returned. A separate raw HTTP gate now verifies that rewritten-route
behavior before an owner read can pass. The earlier failure stays sealed.
The separately reproduced public scanner-check defect is repaired through
`check_host` while preserving the entire download method. The
[qualification record](../VERIFICATION-20261115-simple-backup.md) distinguishes
original failures, native controls and final owner results.

File bytes, active-plugin state and administrator password/activation-key
fingerprints must remain unchanged. Sessions and jobs must stay empty. These
comparisons do not claim a complete database audit. Ordinary audit logs persist
until teardown; target and host-console state are isolated for each invocation.

Each WordPress stack has two containers: app 0.5 CPU / 384 MiB / 128 PIDs and
database 0.5 CPU / 512 MiB / 128 PIDs. Unrelated Apache uses one container at
0.25 CPU / 128 MiB / 128 PIDs. All use init and before/after OOM/PID checks. Only
HTTP has a random loopback port; the database stays internal. The host Framework
console runs outside target cgroup limits with isolated configuration/metadata.

The guarded runner refuses existing containers or a held global lock, and tears
down its stack and volumes after success or failure. The campaign independently
checks exact former container/network/volume identities and lock release before
the next run. Unrelated images and volumes are preserved. Evidence is retained
under ignored `tmp/module-target-tests/` and read-only local exports.
