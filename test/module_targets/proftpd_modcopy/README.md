# ProFTPD mod_copy and PHP execution

One disposable container runs genuine ProFTPD and PHP's HTTP server. It publishes
FTP 2121 and HTTP 8080 on separate random loopback ports. The Framework console
runs on the host. No database or second target is required.

The shared recipe builds affected **1.3.5** from Debian's original source archive,
without applying Debian patches. The fixed profile builds official **1.3.5a**
revision `379bdb0d413f9489768c29c3a36e7bc854c85395`. Archive SHA256 and installed
`mod_copy.c` SHA256 are checked against [release pins](releases.json). The image
retains build configuration, module list and runtime package versions. See the
[upstream authentication fix](https://github.com/proftpd/proftpd/pull/109) and
[official 1.3.5a release](https://github.com/proftpd/proftpd/releases/tag/v1.3.5a).

The FTP worker and PHP process use UID/GID 33 (`www-data`). The FTP master starts
as root so it can drop worker privileges. The synthetic FTP login is `ftplab` /
`module-target-password`; the exploit uses no authentication. Copy artifacts
and finite proofs use `/tmp/copy` and `/var/www/html/lab`; default-payload FIFOs
and session proofs also use `/tmp`. A foreign web file and configuration are
preserved. The root filesystem is read-only, with bounded writable tmpfs mounts.

Run the serial, cleanup-guarded profiles from the repository root:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  MODULE_TARGET_NAMESPACE=proftpd-local \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  proftpd_modcopy proftpd_modcopy_fixed proftpd_modcopy_disabled
```

Every profile uses one container capped at 128 MiB RAM/swap, 0.5 CPU and 64 PIDs.
The runner applies namespace labels, records exact inputs, allocates random
publications and removes the stack after success or failure. Keep the guard's
shared lock and run these profiles serially. Use a unique namespace for any
separate investigation and remove its stack immediately afterward.

Before any module verdict, Python's standard FTP client proves wrong-password
denial and real authenticated upload/download/delete. On 1.3.5, unauthenticated
`SITE CPFR` succeeds. On 1.3.5a it requires authentication; authenticated copying
still works. With `CopyEngine off`, copying is unavailable while ordinary FTP
remains functional. Positive controls copy `/proc/self/cmdline` through a literal
PHP filename into the web directory and execute exact command bytes as UID 33.
They use the real daemon and PHP interpreter independently of Framework code.

The owning module is then checked repeatedly. The affected profile covers
ASCII, quotes, shell literals, Unicode and CRLF commands, an independently
refused FTP port, the actual default Netcat payload, repeated sessions and a
genuinely unwritable temporary directory. A passive TracePoint records original
method locations/results and actual socket closure. Session proof uses public
shell APIs and physical UID/file/PID checks. Fixed and disabled profiles test
explicit execution refusal; the owner does not implement AutoCheck.

Configuration, binary and foreign-file hashes, file ownership/modes, processes,
socket ownership and cgroup failure counters are compared independently. Session
artifacts must disappear before the test's explicit reset. Finite command
payloads use `AllowNoCleanup=true`; their FileDropper warning and physical files
are retained before exact-directory manual reset. That reset is not counted as
automatic module cleanup.

This lab covers Linux/amd64, the recorded Ubuntu 22.04 packages and PHP CLI's
server. Other PHP versions, web servers, FTP configurations, platforms and
payload families need their own native controls. Native probes add no separate
functional example count. Original failures and harness faults are retained in
the campaign verification report; registration alone does not mean a profile
passes.
