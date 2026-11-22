# LinuxKI genuine-package command acceptance

Run serially from the Framework root:

```sh
MODULE_TARGET_NAMESPACE=my-linuxki-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb linuxki linuxki_fixed
```

The checksum-pinned vendor DEB installs the actual x64 CLI and `kivis.php` on
PHP 7.4.33/Apache. The vendor also provides a Docker deployment; this fixture uses
its DEB instead of archived CentOS repositories. No package binary is committed.
Pins and installed-file digests are in `vendor.json`. The CLI help's actual exit
status is 10. Its loader, help, PHP identity and installed source hashes must pass
before any owner call.

The ordinary package installer attempts its optional LiKI kernel-module setup
and reports unavailable kernel headers. This unprivileged web-component fixture
does not load kernel modules, collect live traces or validate trace rendering.
It needs no host mounts, device access or privileged capabilities. A missing trace
capture is not the command-execution oracle: direct non-root shell execution and
the genuine HTTP page independently write exact Unicode/CRLF bytes, verify UID 33
and remove the file before each owning command.

Four examples cover native prerequisites, the actual reason-bearing check and
ASCII/quoted commands through target 2 with `cmd/unix/generic`. Both command cases
repeat on the same selected module, first with AutoCheck and then without it.
`AllowNoCleanup=true` permits the generic payload and disabled handler through
FileDropper's compatibility gate; these in-memory commands create only the
independently verified proof files, which the test removes in `ensure`.
TracePoint records the real owner, command and HTTP requests/responses; target
file bytes and ownership establish execution. Sessions/jobs and resource-limit
events are checked. The runner creates at most two capped containers, publishes
only a loopback HTTP port and removes its project and volumes on every exit.

PHP in-memory/dropper sessions, default Bash sessions, Linux droppers, other
releases and network/error paths require separate native qualification. A passing
command profile does not establish those paths.

Sources: [vendor Dockerfile](https://github.com/HewlettPackard/LinuxKI/blob/5b04f4b36fd85593cea628f04886a2f1dc6df68e/Dockerfile),
[fixed source change](https://github.com/HewlettPackard/LinuxKI/commit/10bef483d92a85a13a59ca65a288818e92f80d78).
