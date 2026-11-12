# Salt master ZeroMQ collection lab

Three serial profiles run genuine Salt masters: affected 3000.1, fixed 3000.2,
and 3000.1 with three additional local publisher accounts. They exercise
`auxiliary/gather/saltstack_salt_root_key` through its public `run` entrypoint.
The [fixed release](https://github.com/saltstack/salt/releases/tag/v3000.2)
restricts methods exposed over the clear transport for CVE-2020-11651.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb saltstack_3000_1 saltstack_3000_2 saltstack_3000_1_acl
```

The Dockerfile pins the official amd64 Python 3.7.17 base by digest and installs
official PyPI Salt release archives and runtime wheels by exact URL and SHA256.
Using the release archives avoids the version metadata problem described in
the vendor's release notice. Python 3.7 supports this old Salt code without
application compatibility patches. Salt's native Cryptodome import path uses
the pinned `pycryptodomex` package. No Salt source or network response is replaced.
Normal `salt-master` starts the service; there is no API server or SSH daemon.

Native controls compare eight installed vendor files with verified release
archives, check runtime package versions and fixture configuration, and use
Salt's own ZeroMQ client. They compare the disclosed key with the actual local
master key, prove rejection of an invalid key, and run an authenticated command
using the real key. The marker is removed and the actual cached successful job
result is checked. Fixed Salt must deny disclosure while still accepting the
authenticated control. The ACL profile produces a larger genuine key map.

Functional examples check repeated collection, SQL credential/service identity,
workspace isolation, hostname resolution, the explicit Dump action, and recovery
after a natively proved refused port. Collected key bytes must match the native
master key and the stored credential. Generated keys are disposable runtime
data; no key is configured in this repository. The module records its disclosed
credential as Untried. These tests do not claim that it records a CVE or loot.

Each profile has three containers capped at **1,216 MiB and 1.5 CPUs**:
Salt 320 MiB/0.3 CPU/128 tasks, reporting PostgreSQL 128 MiB/0.2 CPU/64 tasks,
and Framework 768 MiB/1 CPU/256 tasks. Only ZeroMQ return traffic is published
on a random loopback port. Keys, caches, logs and reporting data use bounded
tmpfs. No named volume, privileged container or Docker socket is required.
Complete teardown precedes the next profile.

Registration and native preflight do not qualify a module. Consult the campaign
verification reports for actual results and recorded failures. This lab does
not qualify 2019.x releases, the RCE module's four master/minion payload targets,
Salt API vulnerabilities, or post modules. Those require separate controls.
