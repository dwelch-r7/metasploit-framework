# Native MySQL UDF execution

The `exploit/multi/mysql/mysql_udf_payload` lab passes nine cases on genuine
MySQL 8.0.36, with the module's declared Linux x86 payloads on an x64 server.
It uses the existing Framework x64 UDF unchanged and deliberately makes only
the plugin directory writable by `mysql`, with `secure_file_priv` unrestricted.
The daemon remains UID 999. These are intentional vulnerable lab prerequisites.

From the repository root:

```sh
MODULE_TARGET_NAMESPACE=local-mysql-udf bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb mysql_udf
```

Two containers run at once: MySQL at 640 MiB/1 CPU and the reporting database
at 384 MiB/0.25 CPU, each limited to 128 PIDs. Ports publish to ephemeral loopback
addresses. The MySQL base image is pinned to a digest and wget to an observed
package version. The setup package probe passed at 1 GiB; runtime tests use the
smaller limits above. The selected functional run takes about six minutes here,
including fresh database/console startup and both native payload calibrations.

The guarded runner serializes participating worktrees, labels its namespace,
and removes its created project after testing. During this campaign, completed
stacks are removed immediately and unused task-created containers up over an
hour are removed after ownership is verified. Unrelated containers are preserved.
All credentials in this lab are disposable test values.

Native SQL controls verify the actual UDF bytes, command execution, wget fetch,
permission denials and both real payload/handler families before owner calls.
The nine cases cover:

- Fresh UDF installation and reuse, with repeated shell sessions.
- Forced replacement and repeated Meterpreter sessions.
- Fresh/reused/forced execution through a genuine MySQL session, preserving
  its connection ID, user, database and usability.
- Wrong credentials, FILE denial, mysql.func catalog denial, an unwritable
  plugin directory and a refused connection.

Passive owner traces record the actual generated ELF hash. Target-side hashes,
responsive session commands, marker bytes, UID, remote PID disappearance and
persisted session closure provide the execution/recovery evidence. Generic error
text cannot pass a negative case without an actual owning-method entry.

The module intentionally leaves its UDF and executable behind. Tests record the
new files, then explicitly drop the function and remove only files created in
this fresh lab, checking their recorded hashes before deletion. This is lab
reset, not automatic module cleanup. Baseline files must remain unchanged.

The existing UDF artifact has SHA256
`c071278f921475bc6f252b10b771dda4948596ef6d81b689bd936a2a9058b5cc`.
No new binary is added. The related
[upstream source/build project](https://github.com/mysqludf/lib_mysqludf_sys/tree/87fda590ee8fd6e5adf25d5fd3a80ffae1b3f7c2)
does not establish byte-identical provenance for Framework's artifact; its
published binary differs. This lab tests the actual existing Framework bytes.

Windows, Linux x86 servers, other database releases, TLS authentication and
staged payloads remain unqualified. Linux x64 payloads work in the native control
but are outside this owner's declared x86 payload compatibility and are not
counted as owner coverage. See the [verification record](../VERIFICATION-20261118-mysql-udf.md)
for baseline defects, repairs and sealed evidence.
