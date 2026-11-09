# Kubernetes discovery and pod execution

The selected checkpoint covers **122 runtime modules, 57 families and 780
functional cases**, adding two modules and twenty-five cases to the
[ZooKeeper checkpoint](VERIFICATION-20261109-zookeeper.md). Selected profiles
have exact counts, no failures/pending/outside errors, current recorded input
hashes and owned teardown. The repository-wide goal remains active; no PR was
created or full local RSpec suite run.

## Actual cluster and meaningful paths

The [K3s lab](kubernetes/README.md) runs official digest-pinned K3s
v1.32.3+k3s1/containerd with genuine API server, kubelet, scheduler and Python
3.11.11 pods. It is a privileged nested runtime sharing the engine kernel and
devices, with private PID/cgroup/network namespaces, tmpfs and four task-owned
volumes. It mounts no host files, existing kubeconfig or Docker socket. Only
the API is randomly published on loopback. Native mount/namespace evidence
distinguishes the task container root from the engine host.

Each final profile performs thirty-two independent native operations. Real
kubectl/HTTPS validate RBAC, resources, empty/missing paths, authentication,
repeated command proof and pod creation/deletion. An in-pod urllib request uses
the actual projected token, namespace, CA and service environment and verifies
the internal API certificate before receiving HTTP 200.

Fifteen enumeration cases cover every action, named resources, JSON/table,
exact native secret bytes and five loot artifacts per collection, fallback
namespaces, empty lists and 401/403/404. Secret collection repeats twice per
format. The [execution profile](kubernetes_exec/README.md) adds ten cases across
all four delivery targets: Unix commands, interactive WebSocket shells, Linux
droppers and Python Meterpreter. Real session discovery/routing must reach the
pod and produce fresh native identity/file proof; session counts alone do not
suffice. Created pods remain as documented, then operator cleanup restores
state using their unchanged thirty-second native deletion grace.

## Failure classification and narrow repairs

| Run/profile | Cases/failures | RSpec seconds |
| --- | --- | --- |
| `20261109T223058-d8d84d/kubernetes`, original | 15/3 | 125.771550 |
| `20261109T223626-78560e/kubernetes`, corrected harness | 15/0 | 59.885633 |
| `20261109T223626-78560e/kubernetes_exec`, original | 10/5 | 280.284667 |
| `20261109T225014-7b9d4d`, isolated original exec | 1/1 | 131.969135 |
| `20261109T230256-1c5a11/kubernetes_exec`, repaired | 10/0 | 350.541648 |
| `20261109T230256-1c5a11/kubernetes`, repaired | 15/0 | 66.489779 |

The first three enumeration failures are harness assumptions about compact
empty JSON and unordered outer authorization-rule entries. Thirteen real JSON
captures support the correction; every field and each rule's content remains.
Four original execution failures concern harness timing, option validation,
missing-pod error wording and a secondary assertion TypeError. Their corrections
preserve native grace, select the actual routable listener, use the captured
WebSocket error and assert Arrays explicitly. Scoped recovery occurs after
state capture and cannot turn a failure into a pass.

Two actual owning defects are independently reproduced. Both modules discover
`module-lab` through a real pod Meterpreter, then use the blank datastore
namespace in API requests. The isolated original exec sends
`/api/v1/namespaces/pods/fixture-pod/exec?...` and receives 403 while native
certificate-verified in-pod requests to the correct namespace receive 200.
Three enumeration and two execution call sites now use the existing namespace
accessor. Explicit nonblank options retain precedence. All nine shared
Kubernetes API helpers remain byte-identical.

Matched focused regressions improve **17/5 to 17/0**, including seven shared
examples; the parent independently repeats 17/0. An earlier 17/7 unit attempt
omitted existing `name: nil` keywords and remains a harness failure. Later
fixture provenance appends the original exec trace without changing consumed
namespace/pod inputs or assertions. Four new Ruby files lint clean. Exec
retains three inherited metadata offenses and tidy status 2; auxiliary tidy
passes. Documentation retains two existing universal-SESSION warnings. Neither
human Scenarios section changes.

## Evidence and limits

The parent imports and byte-verifies all **142** regular files in the final
combined invocation, then independently verifies both profiles' current 56/37
input sets. The original 37/54/37/56 sets reconstruct exactly from retained
snapshots. The worker audits seven projects and twenty-eight recorded volumes
absent; the parent independently rechecks both imported final projects and
their eight recorded volumes. No shared runner, API helper or project
dependency changes were needed.

The durable `kubernetes-module-validation-20261109-f9740c503d0a` export retains
all baselines, the isolated original exec trace, native feasibility/isolation,
exact source variants, units, checks and qualification provenance. The parent
independently rereads all **546** checksum entries. Its `SHA256SUMS.json` digest
is `cadf4e502449500c9e67cd2c1259d405a0c7a90944e1a1b79e4df3d75f598fca`.

This qualifies Linux amd64, one K3s release and root-owned Python pods. Other
distributions/releases/architectures, Windows/nonroot pods, alternate auth
plugins and database persistence remain unqualified. The matrix is not every
Cartesian combination of payload/session/permission. Recorded hashes are not
the whole dependency graph. Aggregate selection is
`tmp/module-target-checkpoint-kubernetes-current.json`; Grafana and WordPress
admin remain unqualified there. RabbitMQ/Erlang and Solr retain separate work.
