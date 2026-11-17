# Rsync credential post-module target

This target exercises `post/multi/gather/rsyncd_creds` through genuine root and
ordinary-user shell sessions against rsync 3.2.7 on Ubuntu 22.04. Configuration
exists only on the target. Native rsync authentication, exact file download and
permission checks run before and after the owning module calls; PostgreSQL
queries check actual session-origin credentials and Untried login records.

Use the repository's supported Ruby/gem environment and a running Docker engine:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb rsync_creds
```

The guarded runner builds the existing [rsync image](../rsync/Dockerfile), starts
the two-service [Compose stack](compose.yaml), discovers its random loopback
ports and writes transcripts, native observations and RSpec JSON beneath
`tmp/module-target-tests/<run>/rsync_creds/`. It removes the stack, its attached
networks and its database volume afterward. Do not run this profile alongside
another target stack. CPU, memory/swap and PID limits total 0.75 CPUs and 640 MiB,
with init enabled and Linux/amd64 declared for both containers.

The image pins Ubuntu 22.04 by digest and verifies the installed rsync package
`3.2.7-0ubuntu0.22.04.7`. Its real daemon serves a protected `locked` share using
the lab-only `labuser:labpassword` secret in a root-owned mode-0600 file. An
ordinary `labuser` shell can read the global configuration but cannot read that
secret or the root home. Default and custom root-home configurations contain the
same configuration bytes as the running daemon. Correct authentication and
download succeed; wrong authentication fails. Selected configuration, secret,
passwd and proof-file hashes and the daemon PID must remain unchanged.

Five functional cases cover global collection and a same-instance repeat,
default home enumeration with missing user files, an unreadable secrets file,
a missing selected daemon configuration with enumeration disabled, and a custom
home filename used after a missing global configuration. Credential assertions
include the exact password, origin session, service/port and Untried status.
Console completion alone is insufficient. Each case proves its actual session
UID, closes the remote process and Framework registration, checks database
session closure and removes only hash-checked generated payloads and markers.

The owner declares shell sessions only. Framework-generated ELF delivery is a
session prerequisite. Transport, parser, rsync daemon and database persistence
are real in these functional tests. The separate
[focused contracts](../../../spec/modules/post/multi/gather/rsyncd_creds_spec.rb)
use doubles for transport, Framework/session metadata, persistence and output;
they exercise the real owner/parser with captured daemon files and explicit
missing, empty and unreadable inputs.

This profile covers Linux/amd64, the pinned package, default port 873 and the
shown configuration grammar. Other operating systems, architectures, session
types, alternate daemon ports, global INI inheritance, other credential formats
and transport-disconnect handling remain unqualified. The existing owner has no
`check` method. See the [verification report](../VERIFICATION-20261117-rsync-creds.md)
for preserved setup failures and the owner-only before/after comparison.
