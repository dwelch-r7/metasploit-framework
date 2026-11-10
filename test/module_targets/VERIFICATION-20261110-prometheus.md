# Prometheus configuration and exporter qualification

The selected checkpoint covers **131 runtime modules, 64 families and 878
functional cases**, adding two modules and eighteen cases to the
[Solr checkpoint](VERIFICATION-20261110-solr.md). Every selected result has
exact counts, zero failures/pending/outside errors, current recorded input
hashes and owned teardown. The repository-wide goal remains active. No PR was
created or full local RSpec suite run.

## Genuine targets and observed results

The [Prometheus lab](prometheus/README.md) uses official pinned Prometheus
2.39.1 and 3.2.1, node_exporter 1.9.1 and the checksum-verified official
node_exporter 0.15.2 binary. The legacy Docker image uses retired schema-1
manifests, so its actual binary runs on a pinned modern base. Genuine static,
DNS, file and authenticated HTTP discovery produce seven healthy scrape targets.
Apache authenticates and proxies the actual exporter; it does not emulate metrics
or the Prometheus API.

Sixty-five independent controls comprise thirty-seven HTTP requests and
twenty-eight native commands. HTTP results include twenty-nine 200s, six 401s
and two 403s. Native tools verify versions, configuration, metrics, PromQL,
uname, mounts and network fields. The legacy promtool naming diagnostic is
explicitly retained as exit 3; all other commands return zero, and real ingestion
and queries independently validate those metrics.

| Invocation | Cases/failures | RSpec seconds | Classification |
| --- | --- | --- | --- |
| `20261109T235013-dc6af6` | 18/18 | 122.342376 | No first prompt, BOOT, native suite or module execution |
| `20261109T235710-83dfde` | 18/6 | 95.882958 | Unchanged retry; native controls pass, helper defects reproduced |
| `20261110T000648-727fd2` | 18/0 | 69.017898 | Final qualification, 49 current inputs and owned teardown |

The final suite performs twenty-six module completions and checks sixteen loot
artifacts. It covers root/subpath, accepted/missing/rejected authentication,
empty configuration, metadata-only exporter output, unrelated genuine services,
exact returned YAML/target data, credential references and repeated collection.
Target comparisons exclude volatile scrape timing/error/health fields; raw
documents are retained and every configured scrape target must separately be up.
Positive results reject runtime exceptions and failing banners.

## Reproduced helper defects and evidence limits

Both module sources remain unchanged. Their shared helper discarded explicit
DNS-discovery ports, omitted adjacent static Basic-auth fields and misparsed
quoted metric labels. Three port/static cases and three quoted-mount cases fail
against the original helper after all native controls pass. A real owned mount
at `/data/metrics,"quote"` provides the filesystem regression. Escaped quote,
backslash, newline and quoted-brace parser boundaries additionally use derived
focused cases. A proposed backslash mount was not statable by the exporter
itself and is retained as a producer limitation, not a Framework defect.

The helper now preserves the explicit port and distinguishes password-file
references/redacted values from plaintext static passwords. Real API YAML masks
inline secrets as `<secret>` and exposes password-file references. Both API
versions expose the public fixture's HTTP-discovery URL userinfo unchanged;
no hidden-password recovery is claimed. The new static reporting branch has a
focused plaintext/credential guard test. Database persistence is outside the
functional profile, and inherited discovery reporting remains unchanged.

The metadata-only exporter still emits `build_info`, so the zero-sample branch
is not exercised. Windows exporter, actual provider-specific cloud discovery,
every discovery provider and physical-host information remain unqualified.
Container data describes its namespaces and the shared Linux engine kernel.

## Verification and retained integrity

Matched focused tests improve **50/9 to 50/0** with only the owning helper
changed: thirty-three existing helper examples, ten new regressions and seven
shared examples. The parent repeats all fifty against a migrated disposable
PostgreSQL database, with zero pending/outside errors, then independently checks
its database volume absent. Initial Rex::Text load-order/keyword-hash diagnostics
are retained separately and excluded from that comparison. Four changed Ruby
files lint clean; both module docs pass their checker and preserve human Scenarios.

The original functional input set has 42 keys; the final set has 49 after
explicit unit/capture dependencies and documentation additions. Of the original
42 files, thirty-nine remain byte-identical, the original helper is directly
preserved, and original README/manifest bytes are reconstructed by reversing
known insertions and requiring their immutable recorded hashes. This is not
described as a source-only functional comparison. No timeout was increased or
startup cause inferred from the retained pre-prompt timeout.

The parent imports and byte-verifies all **74** regular files, including hidden
files, in the final invocation, then verifies all 49 inputs against current source.
It independently audits the final runner project and seven volumes absent.
The worker audits four projects, its unit database and twenty-nine recorded
volumes absent. The durable `prometheus-module-validation-20261110-7a8cdde015f`
export retains failures, native controls, original inputs, source freezes and
separate repair/lab commits. The parent independently rereads all **360**
checksums; `SHA256SUMS.json` digest:
`e6b1f57e3a8efc4ffe7678be3bb7e353998a8550e6a750b2d23385cde2d4e77a`.

Aggregate selection is `tmp/module-target-checkpoint-prometheus-current.json`.
Declared inputs are not the complete dependency graph. Shared Fetch ownership
cleanup is under separate native-backed investigation; its repair and affected
Solr/ActiveMQ requalification are not included here. WordPress admin and Ansible
node deployment remain unqualified; capture-protocol work continues.

The last inspected published Grafana revision `205c8ecca90` has eight successful
CI workflows, Verify failing one of 16,971 examples, and Meterpreter acceptance
queued. An isolated eight-example invocation still fails one and concerns an
OpenSSL NTDS-extension short-name fixture. Its source/test causality remains
under investigation; these module results do not establish green repository CI.
