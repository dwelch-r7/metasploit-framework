# pyLoad JavaScript evaluation targets

These four profiles use unchanged LinuxServer pyLoad images, pinned to their
Linux amd64 manifest digests in [releases.json](releases.json). The normal S6
entrypoint starts pyLoad as UID/GID 1000. Each profile contains one pyLoad
container and one small PostgreSQL container for Framework reporting. Both
application listeners bind to ephemeral loopback ports on the host.

| Profile | pyLoad | Original pyimport injection | js2py sandbox escape |
| --- | --- | --- | --- |
| `pyload` | 0.5.0b3.dev30 | Permitted | Permitted |
| `pyload_dev31` | 0.5.0b3.dev31 | Blocked | Permitted |
| `pyload_dev85` | 0.5.0b3.dev85 | Blocked | Permitted |
| `pyload_dev87` | 0.5.0b3.dev87 | Blocked | Blocked |

The native controls establish these contrasts before interpreting module output.
They exercise the real login UI, correct and incorrect authentication,
authenticated and anonymous APIs, AES-CBC encrypted link collection, actual
package/link database rows, deletion and a second collection. Their harmless
injection markers must contain exact bytes and belong to UID 1000. The same
controls run after the owner tests; source hashes, users, configuration and the
main process must remain unchanged.

The actual Click'N'Load addon proxies port 9666 to the web server on port 8000.
The web server also accepts the literal `Host: 127.0.0.1:9666`. This is independent
of the destination port. A different external Host, including a dynamically
mapped destination port, receives HTTP 403. The sandbox module tests both
listeners; the older module retains its documented CNL-only behavior.

Run profiles serially with the repository's configured Ruby and bundle. The
native executable prerequisite also uses an existing host `nasm` installation;
the tests do not install dependencies. Callback connectivity is independently
calibrated from the application UID before any module session is attempted.

```sh
command -v nasm
```

Run the guarded suite:

```sh
MODULE_TARGET_NAMESPACE=pyload-local DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  pyload pyload_dev31 pyload_dev85 pyload_dev87
```

The guard shares a host lock across worktrees and refuses lingering containers
in the selected namespace. The runner records ownership and removes each
finished stack and its volumes before starting the next. Remove only objects
from your own namespace/project if interrupted; never use a global prune.

`pyload_target_spec.rb` invokes the public owners through msfconsole. It covers
reason-bearing checks, AutoCheck, disabled AutoCheck, exact command bytes,
reused module instances, real session use and reporting. The older module's
command, Python and Linux-dropper targets are distinct paths. The sandbox
module's command and Linux-dropper targets run against the primary listener.
An independently assembled harmless executable calibrates x86 and x64 first.
An unavailable x86 host capability is recorded explicitly and does not qualify
the module's x86 path. The fixtures do not install another emulator or runtime.

These are disposable vulnerable services with the vendor default credentials
`pyload` / `pyload`. They belong on an isolated development machine.

Primary provenance:

- [Original pyimport research](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad)
- [Vendor pyimport mitigation](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d)
- [Sandbox-escape research](https://github.com/Marven11/CVE-2024-39205-Pyload-RCE)
- [Vendor sandbox-escape advisory](https://github.com/pyload/pyload/security/advisories/GHSA-r9pp-r4xf-597r)
- [LinuxServer image source](https://github.com/linuxserver/docker-pyload-ng)

The four package releases and selected application source hashes are explicit;
this matrix does not infer every intermediate or later release's behavior.
