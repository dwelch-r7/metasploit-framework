# Sudo chroot native and local-owner controls

```sh
MODULE_TARGET_NAMESPACE=my-sudo-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb sudo_chroot sudo_chroot_fixed
```

The profiles build genuine sudo 1.9.16p2 and fixed 1.9.17p1 from official release
archives with SHA256 verification on pinned Ubuntu 24.04. They run serially as
UID1001 using one 128MiB/0.5CPU/64-PID target, read-only root and bounded tmpfs.
There is no privileged flag, added capability, host Docker socket or published
service port. Ordinary default Docker capabilities permit the real setuid sudo
and chroot path; a no-new-privileges policy would change that prerequisite.

Native controls require real unprivileged compiler/shared-library operation,
ordinary sudo denial, benign NSS denial, two actual root-owned proof files on
the affected build and two denials on the fixed build. Exact source version,
installed binary hash, original UID, proof nonce, effective UID transitions,
complete selected configuration/foreign-file hashes and resource events are
recorded before any owning call. Native operations remove their created tree.

Each profile then creates real Linux shell and Meterpreter entry sessions from
unmodified Framework payloads/handlers. Post-bootstrap events, responsive public
session APIs, physical file bytes/UID and native PID/birth identity gate owner
execution. Actual repeated checks and AutoCheck commands use the original local
module and its compatible `cmd/linux/http/x64/exec` payload. Before selecting the
owner, the real fetch producer/handler executes both exact commands as UID1001,
proving HTTP delivery, generated ELF execution and quoted Unicode/backslash/CRLF
file bytes. Owning delivery must produce those bytes as UID0. The fixed
profile must refuse before its exploit body. The original selected session must
remain usable, keep its identity and cwd, and permit a second run.

Finite commands explicitly set `AllowNoCleanup=true`; the normal Framework
cleanup guard otherwise refuses these payloads before AutoCheck or exploitation.
The tests record preservation failures and manual resets separately from actual
root execution. This opt-in must not be reported as automatic-cleanup coverage
for default session payloads.

The fetch payload's default `FETCH_DELETE=false` intentionally retains its ELF.
Tests capture the absent-before file's ELF bytes/hash/UID and explicitly remove
that known payload artifact. This is recorded lab reset, not automatic payload
cleanup. Module wrapper/NSS cleanup is independently observed afterward.
Unexpected artifacts and
cwd changes fail strict assertions. The recorded manual fixture reset restores
cwd, gracefully closes the entry session and removes only a complete captured
tree created in the fresh container's originally empty `/tmp`. It does not count
as automatic module cleanup. Original system configuration and the foreign file
must remain unchanged. The guarded runner removes the namespaced stack on every
exit, including failures and interruptions.

Registration is not a passing result. Consult the dated verification for actual
outcomes and separate native, fixture, module and cleanup failures. These profiles
cover root command delivery from both entry APIs. Default/root callback payloads,
other payload families, distro packages/backports, alternate writable paths,
compiler denials and wider version boundaries remain further work. No database
reporting persistence is claimed.

Primary provenance:

- [Upstream fixed release](https://github.com/sudo-project/sudo/releases/tag/v1.9.17p1)
- [Buildroot source archive checksums](https://lists.buildroot.org/pipermail/buildroot/2025-July/781918.html)
- [Researcher's real NSS mechanism](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

Only the actual sudo binaries establish vulnerability behavior. No simulated
sudo, NSS service, session or privilege result is substituted.
