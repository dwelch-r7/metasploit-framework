# FreeSWITCH execution validation

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  test/module_targets/freeswitch_execution/run.rb
```

This lab is under development. Dated verification reports establish actual
qualification; a manifest or successful build alone is not proof of a module
result. The first catalog exercises public checks, repeated foreground command
execution, wrong/default/Unicode passwords, genuine ACL and unrelated-service
refusals, and a native-proven closed port. Session and Linux dropper delivery
families still require their own native calibration and functional coverage.
Windows targets require a suitable Windows environment.

The original pinned FreeSWITCH 1.10.10 image contains Bash and minimal Perl but
lacks telnet, curl and wget. The execution fixture adds exact distribution
packages from the immutable 1 January 2026 Debian snapshot. Normal apt signature
verification remains enabled; only that historical source's expiration check
is disabled, following [Debian's snapshot instructions](https://snapshot.debian.org/).
The [package catalog](tools.json) records exact versions, package hashes and the
SHA-256 of the independently downloaded package index. Package signatures are
validated during the build. The Dockerfile is the complete build recipe; no
opaque executable is checked in.

All six original engine/module/client/entrypoint hashes must remain unchanged.
The new tooling's hashes, complete installed-package manifest and package
verification are checked independently. Missing metadata must match the exact
ordered exclusions of the native slim-image configuration; unexpected missing
files and checksum differences remain failures. All differences are recorded. The genuine external native client
proves authentication, version, loaded module and exact system output before
and after owning calls. No server responses, owning methods or authentication
checks are replaced. Passive packet capture records the real event-socket
traffic, while native filesystem content/UID and engine/configuration identity
supply independent execution and restoration evidence.

Profiles run serially with three containers. Application profiles cap total RAM
at 1,664 MiB, CPU at 2.5 and tasks at 576; unrelated OpenSSH uses
1,024 MiB/1.9 CPUs/448 tasks. RAM and combined RAM/swap limits are equal.
Published target ports bind only to host loopback. The unchanged resource guard
refuses more than five containers and any preexisting container; teardown
removes the project's containers, networks and disposable volumes.

The existing [authentication lab](../freeswitch/README.md) remains byte-exact.
The known concurrent credential-core dependency race belongs to its separate
multi-host qualification and is not repaired or suppressed by these fixtures.
