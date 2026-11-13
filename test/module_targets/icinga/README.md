# Icinga Web 2 static-library file collection

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb \
  icinga_2_8_5 icinga_2_9_0 icinga_2_9_5 icinga_2_9_6 icinga_subpath
```

The five serial profiles cover unaffected Icinga Web 2 2.8.5, first affected
2.9.0, last affected 2.9.5, fixed 2.9.6, and an affected application mounted
under `/icingaweb2/`. The 2.9.5 and 2.9.6 profiles use the digest-pinned official
images listed in `vendor.json`. The two oldest profiles use SHA-256-pinned
complete release sources on the same pinned 2.9.5 PHP/Apache base; all 2,466 or
2,568 original regular source files, excluding only Apache URL configuration,
are independently checked against their release manifests before and after. The application PHP source remains unchanged. The small
Dockerfile adds public proof files outside the web root, an unreadable file,
and a separate genuine PHP static server. Only the subpath profile changes the
Apache Alias and RewriteBase configuration.

Independent standard-library HTTP controls run before and after the public
module calls, using the same target address and ports on the Docker network. They compare real text, whitespace and binary responses against
actual filesystem bytes, exercise raw and encoded filename requests, confirm
native fixed/missing/directory/permission refusals, and verify an unrelated
server and a refused port. The application CLI reports the exact upstream
commit; the StaticController checksum must match its release source.

Twelve examples per profile exercise public `check` and `run` calls, twice per
path. They compare persisted loot bytes and metadata, workspace separation,
repeat execution, process/configuration/source identities, session/job closure
and cgroup counters. Empty files and application-level filename refusals are
recorded without asserting they produced loot. Dated verification reports,
rather than this recipe, establish actual qualification.

At most three containers run: target 256 MiB/0.5 CPU/96 tasks, Framework
768 MiB/1.5 CPUs/256 tasks and PostgreSQL 128 MiB/0.2 CPU/64 tasks. Combined RAM
is 1,152 MiB; swap equals RAM. Published target ports bind only to loopback.
The shared guarded runner removes the project's containers, network and
disposable reporting data. These intentionally vulnerable images are lab-only.

The binary fixture contains octets 0 through 255 in order. Recreate it with
`python3 -c "from pathlib import Path; Path('test/module_targets/icinga/files/proof/binary.bin').write_bytes(bytes(range(256)))"`
from the repository root. It contains no executable payload.
