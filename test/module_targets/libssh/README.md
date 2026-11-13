# libssh authentication bypass lab

From the Framework root, with Docker and Compose available:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb libssh
```

The shared runner serializes labs and tears down this project on completion or
failure. Three containers are capped at 1,152 MiB, 2.2 CPUs and 448 tasks in total,
with no swap above the memory limits. Published ports bind only to loopback.
Framework mounts read-only; console and database state are disposable. Each
invocation starts its first console without a metadata seed. Initial image
compilation and console discovery are separate from the functional checks.

The image builds checksum-verified upstream libssh 0.7.5, 0.7.6, 0.8.3 and 0.8.4,
covering the affected/fixed boundary of both branches in the
[upstream advisory](https://www.libssh.org/security/advisories/CVE-2018-10933.txt).
Other releases, operating systems and crypto backends remain unqualified.
The pinned Ubuntu base supplies libgcrypt. Installed package versions and binary
hashes are recorded; apt repositories are not snapshot locked. The old SDKs use
`-fcommon` to retain their original compiler's global-variable semantics on GCC
11. Crypto verification remains enabled.

Each SDK runs its upstream server example. The open variant applies the existing
Framework patch `external/source/libssh/ssh_server_fork.patch`; the guarded
variant retains the application's additional authentication flag. Public API
banner configuration and a disconnect guard support bounded tests; the SDK
authentication code is unchanged. Servers run as UID 10001 with ephemeral host
keys. Password controls use the example's `myuser` / `mypassword`.

Independent Paramiko controls reject wrong passwords and unauthenticated
channels, verify legitimate login/exec/shell, and send the actual message 52
without credential authentication. Bypass commands must create exact proof
bytes as UID 10001 and return real PID/UID/TTY output. Fixed SDKs must reject
bypass channels; the guarded application can refuse shell callbacks despite a
vulnerable library. Native controls also cover delayed execution, an alternative
shell, custom/versionless banners and an unrelated SMTP listener. They run before
and after the module suite.

Paramiko 2.9.3 rejects some valid short RSA encodings emitted by libgcrypt. The
client zero-extends only those encodings before calling the unchanged verifier,
following [upstream handling](https://github.com/paramiko/paramiko/blob/3.5.1/paramiko/rsakey.py).
A genuine captured handshake verifies the original signature and rejects a
tampered signature. No private key is retained.

Functional examples run the real public console module twice per configuration. Execute
covers both SDK branches and PTY settings, delayed output, fixed versions,
banner modes, callback refusal, unrelated/refused services and service-scoped SQL
reports. Shell cases use real sessions, verify exact files and PID/UID/TTY,
observe remote process/socket closure, then use the public close API and verify
SQL closure. Generic CommandShell registration does not consume remote EOF.
No owner method or network result is stubbed. A leaked connection stops later
cases so contaminated state is not reported as additional module defects.

Private artifacts retain calls, native controls, process/socket snapshots, SQL,
session proofs, resource counters, input hashes and cleanup receipts. Qualification
requires a complete passing run. Human-written module guide Usage is preserved.

The [qualification report](../VERIFICATION-20261113-libssh.md) records actual
results, repairs, setup failures and the limits of the covered paths.
