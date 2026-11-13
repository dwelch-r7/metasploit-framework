# Dolibarr contact-collection lab

Run preparation and the functional profiles in one serial pipeline:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/dolibarr/run.rb
```

Qualification belongs in dated verification reports. A healthy container, HTTP
200 or a saved file does not establish correct contact collection.

The lab downloads immutable original 16.0.4/16.0.5 source archives and verifies
21 authentication, installer, model and disclosure files against their pinned
commit hashes. Sources and their GPL license remain in the host cache. PHP
5.6.40 is within the vendor's supported range for both releases. The mysqli
extension is compiled from the original checksummed PHP source in one offline
container, capped at 384 MiB, 0.7 CPU and 96 tasks. Its compiled checksum is pinned;
no binary is committed. The build needs an executable temporary filesystem.
Source and extension caches live under `tmp/module-target-dolibarr-*`.

Application profiles use three containers, capped at 1,408 MiB, two CPUs and
448 tasks: Dolibarr 256 MiB, MariaDB 512 MiB and Framework 640 MiB. The original
CLI installer creates the schema and administrator; original model APIs create
and restore the company/contacts. Configuration is generated in a temporary
filesystem and locked after installation. Vendor code and extension mounts are
read-only. Only application HTTP is published on loopback. The Framework cap includes extra headroom for cold module metadata generation.
Database/document
state is temporary, with no persistent Docker volume.

Independent controls verify login refusal/success, real database records and
anonymous exact/unknown/wildcard email requests. The anonymous client carries
no authenticated cookies. Public cases cover passive checks, repeated JSON/CSV
collection, whitespace/quotes/Unicode in notes, empty contacts, a context prefix,
and the fixed release's default/enabled lookup guards. An unrelated static PHP
site checks product identification and failure handling.

The optional contact-lookup feature on 16.0.5 still returned domain-pattern
matches during native controls, although the module's unfiltered `%` request was
refused. This residual target behavior is recorded separately; the tests do not
claim every contact-disclosure path is fixed or add a new module attack mode.

The installer originally exceeded a 256 MiB database limit; the corrected cache
settings and 512 MiB cap completed with zero memory-limit/OOM/PID-limit events.
A login control without Referer was rejected by genuine CSRF protection; the
client now supplies normal browser headers. No application security check or
vulnerable response is patched or simulated. Existing human Scenarios remain
unchanged. Other PHP versions, database providers and later releases require
separate qualification.
