# WordPress File Manager targets

Owner: [File Manager RCE](../../../modules/exploits/multi/http/wp_file_manager_rce.rb).
The existing [module guide](../../../documentation/modules/exploit/multi/http/wp_file_manager_rce.md)
retains its human-written Scenarios.

These profiles install genuine File Manager 6.0 or 8.0.7 on checksum-pinned
WordPress 5.2.4/PHP 7.3.11 with MariaDB 11.2.2. Vendor source is unchanged.
The official 6.0 download contains another ZIP named `wp-file-manager-6.O.zip`
(capital letter O); both archives are checksum verified before installation.
The fixed package is a deterministic ZIP of official SVN revision 3804192.
All 916 file contents were independently compared with the official 8.0.7 ZIP.

Prepare sources with
`DOCKER_CONTEXT=default BUILDX_BUILDER=default python3 test/module_targets/file_manager/prepare.py`.
The fixed-source preparer accepts the checksum-pinned official download and
repackages it deterministically. When that mutable URL changes, it exports the
immutable official revision with at most four concurrent HTTP requests and
requires the same final checksum. Cached, verified packages need no download.
No additional project dependencies are installed.

Run profiles serially with
`DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb file_manager file_manager_prefix file_manager_readonly file_manager_fixed file_manager_absent file_manager_unrelated`.
Each profile has at most three containers, and the guarded launcher holds the
shared lock and removes the stack and its volumes before the next profile.
Only loopback HTTP ports are published. Limits are 0.5 CPU/384 MiB for the app,
0.5 CPU/512 MiB for the database, and 1 CPU/1024 MiB for Framework, with swap
equal to memory, init processes and PID caps. Unrelated HTTP uses 0.25 CPU/128 MiB.
Negative profiles use a host console and at most two containers.

Independent native controls run before any owning module calls. On 6.0 they
exercise ordinary GIF upload, UTF-8/backslash/NUL `mkfile`/`put`, exact HTTP and physical bytes,
and PHP command execution as the web account through both write paths.
The read-only profile first passes those controls, then changes only the owned
upload directory's permissions and verifies real HTTP 200 application refusals.
On 8.0.7 the unsafe connector must be absent while a genuinely authenticated
administrator can still create a directory, upload a GIF, write UTF-8 text,
retrieve exact bytes and remove the directory through the real plugin backend.
Absent-plugin WordPress and unrelated HTTP have separate health controls.

The affected profiles exercise both `COMMAND` values. Root cases include
command-only PHP, a PHP shell, single-stage Meterpreter and the unchanged staged
Meterpreter target default, with repeat executions and AutoCheck-disabled
command cases. Subdirectory cases cover both commands and the default payload.
Native handlers calibrate each selected session payload through both write
commands first. The genuine 6.0 connector strips NUL and POST backslashes, so native
`put` requests preserve them explicitly and require exact on-disk/HTTP bytes. Tests verify remote
proof and transport closure, and require session-driven physical payload-file
cleanup before explicit operator recovery. Command-only payloads require
explicit operator file recovery because they create no cleanup session.
Apache workers can remain after a request; their continued existence does not
substitute for a session-transport observation.

Both command modes are retried on fixed, read-only, absent and unrelated targets
with AutoCheck enabled and disabled. An HTTP 200 JSON error is a failed file
operation. A passive version result does not establish active vulnerability.
The official 6.8 and 6.9 version archives were unavailable during preparation;
these profiles establish no runtime coverage for those releases. Official 5.9
source needs separate investigation before making a lower-bound claim.
The human module guide and its Scenarios remain unchanged. Dated verification
reports record completed executions, actual results and remaining limits.
