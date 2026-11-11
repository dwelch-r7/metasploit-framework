# Gopher menus and service reporting

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb gopher
```

The genuine documented `prodhe/gopher` image is pinned to its platform manifest.
Its bundled Go source matches vendor commit
`971d4ad174ae17943b47d6fbaf2c437eb1d9257d`; the actual source and image identity
are independently checked. The original command, executable and protocol
handler are retained. Read-only content maps supply root/nested/spaced selectors,
information, Unicode, explicit locations, empty menus and a 512-row menu over
32 KiB. The server's real missing-selector and unsupported-row responses are
captured before deriving module expectations. Native clients read through EOF
and retrieve an advertised file to prove the target is serving actual content.

A normal bundled BusyBox HTTP daemon provides a genuine unrelated service.
The independent client verifies HTTP file bytes and records its response to an
empty Gopher selector. PostgreSQL authenticates real native clients and stores
the module's actual service records, including menu bytes, service identity,
deduplication and ordinary console CSV export. No report API is stubbed.
The byte bound is also tested against the genuine large menu twice, followed
by a successful default-bound read in the same workspace.

Three containers run serially as one project, capped at 960 MiB and 1.4 CPUs:
Gopher 64 MiB/0.2 CPU, PostgreSQL 128 MiB/0.2 CPU, Framework 768 MiB/1 CPU.
PostgreSQL uses bounded tmpfs; no Docker volume is needed. Published ports bind
only to host loopback. Native pre/post controls check unchanged source/content,
process identity and resource events, and prove port 1 is refused from the owning
console's exact network namespace and UID/GID. All project resources are removed.

Registration is not qualification. Passing examples, current input hashes,
independent native controls and exact cleanup are required. This implementation
normalizes unknown item types into error records; these tests do not claim all
Gopher extensions or every possible server implementation.
