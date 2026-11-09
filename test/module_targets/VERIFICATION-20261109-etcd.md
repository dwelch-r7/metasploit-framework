# Native etcd qualification

The selected checkpoint covers **119 runtime modules, 53 families and 746
functional cases**. Every selected profile has exact counts, zero failures,
pending or outside errors, current recorded input hashes and owned teardown.
This adds two modules and sixteen cases to the
[preceding checkpoint](VERIFICATION-20261109-credential-files.md). The broader
goal remains active. No PR was created or full local RSpec suite run.

## Actual targets and meaningful collection

The [reusable lab](etcd/README.md) uses official digest-pinned etcd 3.4.35 and
3.5.18 on Linux amd64. Native CLI and thirty HTTP requests establish genuine
versions, health, nested Unicode/newline/empty values, accepted/rejected v2
credentials, empty storage and a reverse-proxy base path. A disabled-v2 profile
still has a working, independently verified v3 store. Ordinary Apache JSON is
the unrelated-service control. Ten native commands exit zero; vendor CLI
deprecation/health stderr is retained in their receipts. The native probe itself
exits zero with empty stderr in every canonical run.

The final sixteen cases execute twelve version scans and fourteen key-module
runs. Discovery must match the actual server and cluster version fields. Ten
collected JSON files must match the complete native recursive documents, and
repeat reads must preserve every key field, index and value. Only unordered
directory-child lists are sorted by key for comparison. Denied, disabled and
unrelated targets must not create key loot or cause runtime exceptions.

## Failure classification and repairs

An initial native-only preparation failed because directory children changed
order between legitimate reads. The corrected comparison preserves every
field/value and normalizes only those child lists. That setup failure is
retained separately and is not counted as a module failure.

| Canonical run | Cases/failures | RSpec seconds |
| --- | --- | --- |
| `20261109T215231-0f053f/etcd` | 16/10 | 94.421427 |
| `20261109T215843-cd1d46/etcd` | 16/1 | 79.352899 |
| `20261109T220309-498a84/etcd` | 16/0 | 66.742792 |

All three complete naturally with zero pending/outside errors, passing native
controls and passing teardown. The original baseline confirms invalid JSON loot,
false identification of unrelated JSON, unrelated key loot and nonexistent
logging methods on rejected/disabled replies. Correct credentials also fail.
Actual native responses omit WWW-Authenticate; source inspection confirms the
HTTP client's automatic retry requires that challenge, while native Basic
requests succeed.

Separate shared-helper and owning-module repairs validate the version and
action/node shapes, serialize JSON, use existing logging APIs and explicitly
send configured Basic credentials in auto/plaintext modes. Other selected auth
modes remain intact. Both direct helper consumers are exercised by this family.
The first repair passes fifteen cases; its new error-prefixed diagnostic for
ordinary unrelated discovery trips the strict guard. A final verbose-status
correction passes without relaxing any functional assertion.

Focused checks improve **28/15 to 30/0**, including seven shared examples. Two
auth cases were added after the original run, so this is not an identical
thirty-case baseline. The final diagnostic assertion strengthens the existing
unrelated-response case. Captured native bodies and synthetic boundary inputs
are explicitly distinguished. New Ruby files lint clean; production offenses
decrease eight to seven, all inherited. Module tidy and both documentation
checks pass; human Scenarios remain byte-identical.

## Integrity, cleanup and limits

All three functional input sets contain the same 37 keys. Original-to-final
changes are confined to the shared etcd helper and owning key scanner. Both
earlier input sets were copied and hash-verified before subsequent edits. All
final recorded hashes match current source. Raw revisions/paths are preserved.
All three runner projects, their recorded zero volumes and the separate native
prototype project independently audit absent; no fallback cleanup was used.

The durable `etcd-module-validation-20261109-8233740232b` export retains failed,
intermediate and passing runs, hidden metadata, native setup failures/controls,
exact inputs, source/units/lint/docs and four separate commits. All **403**
export checksums were independently reread and verified.

TLS/client certificates, other releases/architectures, unusual version formats,
multi-member failures and v3 key collection remain unqualified. A multiarchitecture
image index does not prove another architecture. These discovery/collection
cases make no session or exploitation claim. No shared runner or Framework
dependency changes were needed.

Aggregate selector: `tmp/module-target-checkpoint-etcd-current.json`; its sole
warning is the unqualified WordPress admin reproducer. Declared hashes are not
the entire dependency graph. Ansible and Erlang execution retain separate
unqualified investigations; Solr remains under native preparation. Fork CI is
assessed independently, with no overall green claim. Sixteen queued workflows
for superseded earlier checkpoints were cancelled; current and already running
or completed workflows were preserved.
