# Superset cookie owner tests

Runtime qualification is recorded separately in the campaign verification
reports. This profile reuses the genuine pinned Superset 2.0.0 native target in
[the shared preparation](../superset/README.md). Its native controls must pass
before owner calls in each invocation. SQL Lab, permalink execution, RCE
sessions, rotated keys, other versions and architectures remain pending
separately.

```sh
nice -n 10 bundle exec ruby test/module_targets/superset_cookie/run.rb
```

One guarded pipeline uses four containers capped at 2,144 MiB and 2.15 CPUs:
Superset, PostgreSQL, canonical Framework, and an Apache gateway. Only the gateway
joins a public bridge and publishes a random loopback port. Start with an empty
container inventory. The shared launcher captures raw results and destroys owned
containers, networks and volumes afterward; cached images remain.

The component command above and the shared guarded `superset_cookie` selector
use the same runner. Its manifest explicitly selects the logical `default`
network through `module_endpoint_network`. The shared selector verifies actual
container/network ownership, an internal network shared with isolated Framework,
and the endpoint's IPv4 address. Extra gateway networks must belong to the same
Compose project. Families without this opt-in retain the single-network rule.

The fourteen selected examples exercise real check/run console entry points,
exact gathered datasource credentials and connected PostgreSQL reporting,
repeat execution, the anonymous-cookie path after a rejected password,
missing admin identity, incorrect key lists,
unrelated HTTP, real cookie retrieval with correct/wrong/absent secrets, key
discovery, missing cookie names, legacy literal-data signing, explicit JSON
session signing with actual administrator identity, and malformed JSON refusal.
Distinct workspaces must start empty. A second credential collection must reuse
the exact persisted rows. Each run begins with an independent fresh console and
no seeded Framework metadata.

Native controls verify installed sources, package identity, initialized SQLite,
genuine user roles, actual login/refusals and independently accepted forged admin
identity before owner calls. Afterward, native controls repeat and require exact
logical account, datasource, dashboard and key-value state equality. These
comparisons do not claim unchanged audit/login-history rows or identical SQLite
file bytes. All raw observations remain available on failures. A failing example
alone does not establish an owner defect; validate its setup and native controls.
