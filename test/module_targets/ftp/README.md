# FTP targets

Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb ftp
```

Three real ProFTPD instances use the same digest-pinned Ubuntu base and public
local credential `module_target` / `module-target-password`. Anonymous access is
read/write, read-only or disabled. Installed OS packages may drift on rebuild;
native version, image IDs and command evidence are retained.

Python's native FTP client independently verifies local and anonymous logins,
rejected credentials, file content, listing and write permissions. Periodic
health checks only authenticate/read, avoiding concurrent write probes.

Tests exercise the version banner, public login check, valid/invalid local
credentials, anonymous credential collection, access checks, FEAT/STAT/SYST and
real listing loot. Anonymous listing cases cover both PASV and EPSV. Every
state-changing module path runs twice and must leave only the original marker
file. TLS, active-mode transfers, other FTP implementations and database-backed
credential persistence remain unqualified.

Framework runs inside the target network so passive data channels need no host
port range. Only random loopback control ports are published. See the
[shared guide](../README.md) for retained evidence and cleanup.
