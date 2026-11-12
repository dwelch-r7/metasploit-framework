# UniFi Network Application Log4Shell target

These targets run the real UniFi controller, its bundled MongoDB and the image's
own Java runtime. The image digests are architecture-specific and their labels
match the pinned maintainer source revisions. Version 6.5.53 contains Log4j
2.13.3; the 6.5.54 control contains 2.15.0. The latter is a control for this
module's CVE-2021-44228 path, not a claim about every later Log4j vulnerability.
`vendor.json` records actual JAR/class hashes from image inspection.

The source-built passive Java agent records JVM identity and the actual JAR and
class bytes used for JndiLookup, ResourceRef, BeanFactory and ELProcessor. It
returns `null` for every class transformation and never rewrites bytecode or
application methods. It sets no JNDI or message-lookup property. The image's
normal entrypoint and application handle every HTTPS request.

`native_probe.py` completes local controller setup through the same APIs used by
the shipped setup UI, including `set-installed`. It verifies valid and invalid
local login, logout, an anonymous account-access refusal, and the normal management
UI. No cloud account, physical device or wireless network is configured. Only a
disposable local test account is created.

Before any owning module call, an independent LDAP responder observes a real
lookup and serves a Java-serialized ResourceRef built from `NativeBeanFactory.java`
using the target's own Tomcat classes. The graph invokes a harmless command that
writes only a controlled marker containing the parent application PID. The host
compares file ownership and PID, actual loaded code hashes, kernel process birth,
account state and cgroup counters. The marker is removed, and the oracle's original
process is awaited. The 6.5.54 control must produce neither callback nor marker.
Binary proof data stays in private artifacts; nothing opaque is added to the repo.

The module suite covers repeated checks, a missing target URI, a deliberately
unreachable callback, generic command execution with AutoCheck enabled/disabled,
check-after-run state, Bash sessions with/without AutoCheck, and rejection of a
Linux fetch adapter outside the module's declared Unix target. Session RPC writes
exact proof, native process/file/socket observations
verify it, and SQL checks bind sessions/vulnerabilities/references to the actual
controller. Cleanup is inspected before fallback recovery; the shared console
reset follows already-empty job/session lists. Native application identity and
local account state must remain stable.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb unifi_6_5_53 unifi_6_5_54
```

Profiles run serially with **three containers** maximum: target 768 MiB / 0.6 CPU /
192 tasks, Framework 640 MiB / 1 CPU / 256 tasks and PostgreSQL 128 MiB / 0.2 CPU /
64 tasks. Memory/swap limits match. The only published port is random loopback
HTTPS. Callback services stay on the temporary Compose bridge. Writable controller
state is temporary; Mongo preallocated journals are disabled using the image's
supported database setting. Log4j, JNDI and authentication protections are unchanged.

The startup heap is 64 MiB, maximum heap 256 MiB, with explicit metaspace, code,
direct-memory and thread-stack limits. Native boot/setup must pass with zero OOM
and PID-limit events before an owning failure can be interpreted. The runner
removes the owned containers, network and temporary state afterward. Tests are
scoped to Linux Unix-target delivery on these exact image/configuration pairs;
Windows, macOS, other image rebuilds, lower affected releases and other controller
features remain separate work. The Linux fetch adapter is incompatible with this
module's current target metadata, so no fetched Meterpreter execution is claimed.

Sources:

- [Maintainer 6.5.53 source](https://github.com/jacobalberty/unifi-docker/tree/60c890a94a09903b7b3276ddd34b9e29c1a507b6)
- [Maintainer 6.5.54 source](https://github.com/jacobalberty/unifi-docker/tree/ebac7803c2eee674d020b4774b1eb129caa9be4f)
- [Original UniFi research](https://github.com/puzzlepeaches/Log4jUnifi)
- [Owning module guide](../../../documentation/modules/exploit/multi/http/ubiquiti_unifi_log4shell.md)
- [LDAP protocol, RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.html)
