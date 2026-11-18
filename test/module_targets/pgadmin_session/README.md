# pgAdmin session deserialization target

Run from the repository root with the existing Framework bundle and Docker Compose:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb pgadmin_session pgadmin_session_prefix pgadmin_session_storage pgadmin_session_fixed
```

Profiles run serially, with one stock pgAdmin container at a time. Each has one
CPU, 512 MiB memory/equal swap, PID128 and init. Only a random loopback HTTP port
is published; Framework uses the host Ruby bundle. The guarded launcher removes
the selected container, named data volume and network even after a test failure.
No PostgreSQL service is needed for this module's login/file-manager/session path.

`profiles.json` pins official linux/amd64 8.3 and 8.4 image manifests, expected
image IDs and matching upstream session/file-manager source hashes. The vendor
entrypoint, authentication, file manager and session handler remain unchanged.
Postfix is disabled and four Gunicorn threads permit callbacks while serving HTTP.
The disposable account is `module-admin@example.com` / `module-target-password`.

Before and after owner execution, independent Python standard-library controls
verify the installed source/version/UID5050, wrong and correct passwords, actual
file upload/exact bytes/deletion, accepted uppercase credentials and both
relative/absolute session-file loading. The benign native pickle canaries execute
on 8.3 and remain absent on 8.4. No host unpickling occurs. Native prerequisite
failure prevents interpreting a failed owner test as a module defect.

The root, URL-prefix and space/Unicode-storage 8.3 profiles exercise the real
check, handler-free command, uppercase credentials, wrong password, unrelated
base path, genuine inline Python Meterpreter and command-shell sessions. Each
family repeats with
AutoCheck disabled and reused console configuration. The prefix uses the
vendor-documented `SCRIPT_NAME=/pgadmin` directly with Gunicorn. Storage uses
`PGADMIN_CONFIG_STORAGE_DIR` set to `/var/lib/pgadmin/Spaced café storage`.
The 8.4 profile checks Safe, normal AutoCheck refusal and forced command
nonexecution, with successful uploaded-file deletion and unrelated-path rejection.

Sessions must register through Framework and its ready event, perform a real file
operation with independently verified exact bytes/UID5050, expose a live target
TCP socket and close that connection. Meterpreter uses its public file API and
retains no extra channels. The Python shell starts a fresh shell for
each command; its public session termination closes the receive loop's peer.
Proof/upload files are checked absent, local sessions/jobs are cleared and native
health plus OOM/PID-limit checks cover the selected scope.

The separate [Meterpreter recovery regression](../pgadmin_session_meterpreter/README.md)
retains strict staged/inline session/file/API/closure tests, including repeats and
channel checks. Earlier staged sessions retain target sockets beyond the shutdown
bound. A source-only BentoML reproduction identifies a connected descriptor
inherited by the service parent; the shared Python TCP stager closes that copy
when stage execution returns. The worker is never forcibly signalled. See the
[BentoML verification record](../VERIFICATION-20261118-bentoml.md) for the replay
and subsequent cross-owner regression results.

The authenticated owner uses the actual uploaded storage path and quotes Cookie
values. Native Request.cookies captures establish octal escaping for UTF-8 bytes;
a Ruby Cookie parser alone does not model that WSGI request path. Unit contracts
cover metadata and wire-format failures with explicitly labeled HTTP doubles.
Paths containing pgAdmin's intrinsic `!` session delimiter are rejected.

Only the selected Linux 8.3/8.4 paths are covered. Windows authenticated/UNC/SMB,
other releases/architectures, TLS, real proxies and transport loss remain
unqualified. Existing human-written Scenarios remain unchanged. See the campaign
verification record for actual results and preserved failed attempts.
