# Planyo file collection lab

Owner: [wp_planyo_lfi_cve_2026_3576](../../../modules/auxiliary/gather/wp_planyo_lfi_cve_2026_3576.rb).
The [original module guide](../../../documentation/modules/auxiliary/gather/wp_planyo_lfi_cve_2026_3576.md)
retains its human-written Scenarios.

These profiles install unmodified official Planyo Online Reservation System
2.7, 2.9 and 3.1 archives into WordPress 6.8.3 / PHP 8.3.28 with MariaDB.
The release catalog pins archive sizes, SHA-256 values and the installed
plugin, proxy and readme sources. Version 3.1 adds an HTTP(S)-only scheme check
and removes localhost from the proxy host allowlist. The directly accessible
vendor `ulap.php` implements the tested file read without requiring a cloud
reservation account. The ordinary remote reservation service is outside scope.

Prepare the official archives and run one profile from the Framework root:

```sh
export DOCKER_CONTEXT=default BUILDX_BUILDER=default
bundle exec ruby test/module_targets/planyo/prepare.rb
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb planyo
```

Other profiles are `planyo_prefix`, `planyo_older`, `planyo_inactive`,
`planyo_fixed`, `planyo_absent` and `planyo_unrelated`. Every related stack has
two containers: WordPress at 0.5 CPU / 384 MiB and MariaDB at 0.5 CPU / 512 MiB.
The unrelated Apache target has one container at 0.25 CPU / 128 MiB. Every
service has an init process, 128 PIDs and equal memory/swap limits. HTTP uses
ephemeral loopback ports. The guarded launcher serializes stacks and removes
the project's containers, networks and volumes on completion or failure.

The plugin creates its normal WordPress state through real administrator
activation. A separate installed-but-inactive profile tests the standalone
proxy directly. Source-generated local files cover text, binary, empty,
Unicode and reserved-character names. A literal `%20` filename distinguishes
percent text from a decoded space. Root-owned mode 0600 and missing files establish real
permission and absence controls for the HTTP user. `/etc/passwd` verifies the
module's default input against actual container bytes. No target endpoint,
response or owning module is emulated.

Before and after module calls, independent HTTP controls verify WordPress
health and actual proxy behavior. File URL path segments and the enclosing
query are encoded separately by the native client. Patched refusal must leave
the ordinary application healthy. Owning operations run twice and compare
exact loot bytes with native file data, including empty files. Before/after
snapshots retain users, source hashes and fixture permissions/content. The
module has no public check; these profiles exercise its file-collection run.

Calibration findings and runtime status are maintained in the
[verification record](../VERIFICATION-20261116-planyo.md). The original human
module guide and Scenarios remain unchanged. Other target/runtime releases and
the external reservation product are not covered by these profiles.
