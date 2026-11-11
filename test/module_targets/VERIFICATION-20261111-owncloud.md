# ownCloud verification — 11 November 2026

The checkpoint is **205 qualified modules, 171 profiles and
1,885 passing functional examples**. The [ownCloud lab](owncloud_phpinfo/README.md)
adds root/subpath deployments, a fixed app and Apache for
`auxiliary/gather/owncloud_phpinfo_reader`. The campaign remains incomplete:
296 documented container hints need review, alongside unhinted candidates.
Registration of 207 sources is not qualification.

## Genuine targets and result

The official ownCloud 10.12.1 amd64 image contains Graph API 0.3.0 and the original
17-byte PHP test file. Native reads verify its SHA256. The fixed-app adapter
installs the complete 0.3.1 app from the verified application layer of the pinned
official 10.13.1 image. **Its core, PHP, Apache and vendor startup remain 10.12.1**;
it does not represent a full 10.13.1 deployment. Live image layers, commands and
full app-tree hashes agree with [profiles.json](owncloud_phpinfo/profiles.json).
The fixed app lacks the PHP test file; PHP itself remains enabled. There is no
replacement HTTP handler, Docker socket or privileged container.

The [vendor advisory](https://owncloud.com/security-advisories/disclosure-of-sensitive-credentials-and-configuration-in-containerized-deployments/)
identifies the exposed Graph API dependency file and notes that disabling the
app alone does not remove it. Historical Marketplace download URLs now return
404. The archived core package omits Graph API; the adapter therefore uses the
complete app from a verified official image layer, avoiding another large PHP
runtime in the local cache. Failed resolutions and package inspections remain
in the evidence.

Final source: `acd3374f0f4d5e8e6cf2deca57eae901520630a4`.
Run: `20261111T231631-f32486`. Manager and all four live observers exit zero; there are no pending or outside-example errors.

| Genuine target | Examples | Failures | Spec seconds |
| --- | ---: | ---: | ---: |
| ownCloud 10.12.1 / Graph API 0.3.0 | 22 | 0 | 270.09 |
| Same vendor app under /owncloud | 22 | 0 | 212.02 |
| Same runtime / Graph API 0.3.1 | 22 | 0 | 283.00 |
| Apache 2.4.62 control | 2 | 0 | 44.76 |

The first console has an observed prompt, BOOT record and two fresh metadata
snapshots without a seeded first cache. Later profiles use only the normal
same-invocation seed, observed and compared byte for byte.

Native Python HTTP/HTML parsing, PHP filesystem/process controls and actual
PostgreSQL/Redis clients independently establish the fixture. Direct PHP paths
redirect; all 16 advertised suffixes expose actual environment fields on the
affected app and fail to expose them on the fixed app. Ordinary status and
accepted/rejected WebDAV authentication remain functional. The application's
own PostgreSQL schema is separate from Framework reporting. PostgreSQL and Redis
accept the public lab credentials and reject incorrect passwords. A refused
port is proved in Framework's actual UID/network namespace.

The final 90 public module calls cover default discovery, every explicit
suffix, both roots, TARGETURI, repeat execution, missing paths and refused ports.
All 46 actual loot files match complete independently decoded native fields.
The 4 default-read traces also contain the entire actual saved body;
independent requests have volatile PHP fields, so their whole bodies are not
assumed identical. Real SQL verifies 156 credential cores, their
156 services and 156 Untried logins, including correct decoded
secrets, resolved addresses/ports, origins and repeat-call deduplication. Negative
calls preserve earlier records in the mixed positive/negative workspace.

SMTP and disabled object-store settings are disclosure fixtures; they are not
authenticated against external services. Object-store secrets are retained in
stdout/HTML loot under the module's existing contract. A collected credential
is not reported as authenticated merely because native fixture controls proved
the underlying account valid.

## Reproduced defects and fixture corrections

The original module returns Strings for explicit ROOT/ENDFILE values and calls
`each` on them. Its field regex omits values containing spaces and stores HTML
entities as credential text. Database reporting reads the wrong datastore key;
Redis host and port are reversed. Configured hostnames also need proper address
resolution for service association. An original completed read creates only the
ownCloud credential despite printing database/Redis values. Actual SQL exposes
that loss independently of completion messages.

The fix returns arrays, decodes native table cells through the existing HTML
parser, uses the extracted database secret, preserves endpoint fields and
resolves names through Rex before reporting. Missing/invalid endpoints warn and
retain the raw loot. Review caught a proposed loss of the existing SMTP
127.0.0.1/25 defaults; the final implementation preserves and tests them.
ROOT requiredness/defaults remain unchanged: empty ROOT already validates.

The identical focused suite, seed 49103, has **46 module examples**. The independent
canonical comparison exits 1 with 35 failures on original source and exits 0
with no failures on final source, with matching spec hash/order. The real module
loader, option objects, HTML parser, URI builder and failure classes run in
process. HTTP, DNS, loot/report boundaries are disclosed doubles; synthetic
nullable/malformed/endpoint controls supplement three genuine captured bodies.
They do not prove SQL persistence or authentication. Human Scenarios remain
byte-identical.

Preserved batches distinguish fixture errors from production failures:

- `20261111T221121-74dfc3`: 66 ownCloud examples are blocked before module calls
  because the probe expected rejected Redis authentication to exit 0 instead
  of its actual exit 1/WRONGPASS. Apache independently exposes the String crash.
- `20261111T222310-5f3eb5`: 68 examples/59 failures: 55 option-crash cases,
  two non-traced harvested-value assertions and two trace-wrapper false positives.
  PHP's legitimate SPL Exception class list triggers the generic helper's
  unanchored error check. Native before/after controls and all 38 cleanup queries pass.
- `20261111T225309-a5ed9e`: the source fix passes root 22/0, fixed 22/0 and
  Apache 2/0. Prefix 22/17 rejects normal unsuccessful discovery probes before
  actual success. Independent checks verify all 23 prefix loot files and
  80 correct credential/service records. The lab now rejects fatal module errors
  while allowing those intermediate discovery statuses. The shared helper is unchanged.

Helpers/spec lint, Python syntax, module documentation and whitespace checks
pass. Canonical module RuboCop exits 1 and msftidy exits 2 solely for the identical
pre-existing duplicate RPORT warning at line 48. A final unit regexp style
finding was corrected before the canonical original/final comparison.

## Resources, cleanup and review

One project runs at a time, with four containers capped at **1,504 MiB/1.65 CPUs**:
ownCloud 512 MiB/0.35 CPU/128 tasks, PostgreSQL 192 MiB/0.2 CPU/64 tasks,
Redis 32 MiB/0.1 CPU/32 tasks, Framework 768 MiB/1 CPU/256 tasks. Apache profiles
have three containers totaling 960 MiB/1.3 CPUs. Live inspection verifies caps,
equal memory/swap limits and loopback-only published HTTP. Each project is removed
before the next starts.

Native pre/post controls preserve environment, app files/version and target
process identity. ownCloud target memory/PID event counters stay clean. All
62 distinct selected input hashes are current. The final 38 independent
cleanup queries verify exact containers, networks, data volumes, project
inventories and an empty global container list on the same Docker engine/context.
The bounded task-local guard handles unrelated tool containers recreated by the
app, outside module qualification.

The final read-only seal has **470 entries**, manifest SHA256
`4e5c5c4c0990823440b57e8d8244f427425f7023e64f721dde9d6f30e638a316`. Evidence is under
`tmp/module-target-tests/20261111T231631-f32486/` and the local
`owncloud-verified-20261111` package. Identical files are linked only within the
package, independently of active source/run files. Earlier source, failures and
worker comparison packages remain separate and immutable.

**Summary:** Genuine affected/fixed collection and refusal paths pass for these explicit-port fixtures.

**What looks good:** Genuine target content, complete loot, real stored records,
repeat behavior, current source and exact teardown agree.

**Concerns:** Hostname-only database configuration is a known remaining
association limitation: the parser leaves its port unset and skips a credential
service record. A genuine hostname-only deployment/actual-port reproduction is
queued; provider defaults must account for MySQL sockets and libpq overrides.
Other app versions, TLS deployments and module execution against MySQL/SQLite
deployments remain unqualified. Existing druid_js, superset_rce_owner and wordpress_admin profiles
remain excluded. Inventory has 18 individual reviews with 0 stale.
New-head CI is assessed separately from local acceptance.

**Suggestions:** Reproduce the hostname-only case next, retaining explicit-port
behavior and avoiding guesses for unknown providers or socket endpoints. Keep
remaining target families serial.

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb owncloud_graph_0_3_0 owncloud_graph_0_3_0_prefix owncloud_graph_0_3_1 owncloud_unrelated
```

Publication is to the user's fork branch. No PR is created.
