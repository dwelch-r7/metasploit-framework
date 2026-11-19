# GNU Inetutils Telnet authentication targets

Three profiles run genuine Ubuntu packages with their normal login/PAM stack.
The Ubuntu base manifests and the `20260210T000000Z` APT snapshot are pinned in
[releases.json](releases.json). A checksum-pinned Ubuntu ca-certificates archive
supplies bootstrap trust roots; APT retains TLS and archive signature checks.
The fixtures install prerequisites inside the images, with no host installs or
new Framework dependencies.

| Profile | Distribution | Exact Inetutils package | Native bypass |
| --- | --- | --- | --- |
| `inetutils_telnet` | Ubuntu 24.04 | `2:2.5-3ubuntu4` | Permitted |
| `inetutils_telnet_fixed` | Ubuntu 24.04 | `2:2.5-3ubuntu4.1` | Blocked |
| `inetutils_telnet_bionic` | Ubuntu 18.04 | `2:1.9.4-3ubuntu0.1` | Permitted |

The fixed contrast concerns CVE-2026-24061. It does not establish that this old
package contains every later security repair. Ubuntu 18.04 is a distinct PAM
and login-history path; a fixed Ubuntu 18.04 ESM package is not included.

The real inetd launches the packaged telnetd on port 23. A small TCP bridge on
port 2323 forwards the same byte stream and deliberately splits server writes.
Both ports bind to ephemeral host loopback ports. The bridge implements no
Telnet negotiation, authentication or command handling. Each profile has one
app container and one PostgreSQL reporting container. Caps total 1.25 CPUs and
896 MiB, with 128 PIDs per container. The independent harmless ELF prerequisite
uses an existing host `nasm` installation; it does not install one. Verify it is
available with `command -v nasm`. Run profiles serially:

```sh
MODULE_TARGET_NAMESPACE=inetutils-local DOCKER_CONTEXT=default BUILDX_BUILDER=default \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb \
  inetutils_telnet inetutils_telnet_fixed inetutils_telnet_bionic
```

The shared guard refuses another guarded run or existing containers in the
selected namespace. Each completed stack and its volumes are removed before
the next profile. If interrupted, remove only objects belonging to your own
namespace and exact project. Never use a global prune.

The native client explicitly selects its username with `telnet -l`: the GNU
client can replace an existing `USER` value whose UID differs from its own.
Controls require a real password login as UID 1001, rejection of a wrong
password, root bypass first/repeat, non-root bypass and rejection of an absent
account. Exact proof bytes and file ownership are checked independently of
terminal echoes. These controls run against both transports before and after
the owner tests. Source binaries, PAM configuration, account files and the
main inetd PID are checked for changes. Login history and ordinary service logs
are retained, including the Ubuntu 18.04 `Last login` state.

The disposable `labuser` account uses `module-target-telnet-password`; root keeps
its image-default locked password. Vulnerable profiles permit remote root
execution by design and belong on an isolated development machine.

Primary provenance:

- [GNU maintainer advisory](https://www.openwall.com/lists/oss-security/2026/01/20/2)
- [Ubuntu affected and fixed package versions](https://ubuntu.com/security/CVE-2026-24061)
- [Ubuntu immutable package snapshots](https://snapshot.ubuntu.com/)
