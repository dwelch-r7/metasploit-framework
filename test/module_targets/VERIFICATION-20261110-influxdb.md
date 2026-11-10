# InfluxDB and integrated checkpoint, November 10

Current hashes, exact passing counts and owned teardown establish **164 runtime
modules, 92 families and 1,220 functional cases**. InfluxDB adds16 cases to the
[Spark checkpoint](VERIFICATION-20261110-spark.md); the full campaign is incomplete.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb influxdb
```

Official digest-pinned InfluxDB1.8.10 uses its unchanged vendor entrypoint as its
native UID0. Three real servers cover authenticated, authentication-disabled and
empty states; real Apache supplies a proxy prefix and unrelated service. Root/root
and reader accounts are explicit public fixtures, not a factory-default claim.

Final invocation `20261110T084454-f428ee` passes16/0 in60.744508 seconds, zero
pending/outside errors, native gate and cleanup pass. All39 selected files remain
current. The owning module SHA-256 stays
`a17238d4e49a5e7bb7502ac0ea73ed4c849ccd3d7707897af6bed51983723966`.
No production/shared runner/SDK/dependency/timeout changes.

Native21CLI/45HTTP controls establish actual version/process, database/user rows,
Unicode/quotes/timestamps, restricted privileges, empty results, credentials401,
permission403, syntax400, missing-path404 and a closed port. Final32 public calls
produce18 exactly compared JSON loot files; sixteen native state audits preserve
the database/user/data state. All branches repeat. Credentials on the no-auth
server are ignored, not validated; this utility does not open sessions.

The first strict native gate exposes CLI nanoseconds versus HTTP RFC3339. An
explicit vendor CLI precision option resolves that observer mismatch before
Framework execution. Original full16/1 (78.759807s), all native/cleanup good,
expects the module's outer connection-rescue text. Actual shared HttpClient prints
refusal and returnsnil first. The sole test expectation correction yields16/0
with original owner and allother38 input hashes unchanged. Both complete runs,
source snapshots, actual prompt/BOOT/fresh parsed metadata receipts are preserved.

Exploratory/native01 aggregate logs accidentally share filenames and overwrite
the first arrays; first-control-results retains response documents/CLI text/source,
but the original aggregate argv log is not recovered or claimed. Native01 and
all later separate-directory transcripts are retained. No setup failure is
classified as a module defect or source-only repair claim.

Parent verifies all454 worker checksum entries,39 current inputs and76 imported
invocation files byte-for-byte at
`/Users/dwelch/.codex/reports/influxdb-module-validation-20261110-1954f855e14`,
SHA256SUMS SHA-256
`87b49e9819336ff4d3957d60f8f92381fd0ad855f25c8162542c177ba368f248`.
Parent lint passes the new Ruby spec; selected dry discovery16 passes. Worker
excluded discovery7 and Python syntax pass. Docs retain exactly seven inherited
warnings/one INFO and all original prose/Scenarios except the exact guide section.
No full local RSpec suite was run.

All38 parent resource checks pass:17 recorded container IDs, three network IDs,
nine anonymous volumes and three exact owned projects are absent. Images remain
caches. Parent receipts: `/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-180984d4bdf`,
13 entries, manifest SHA-256
`ad8005b0492dc6a0b1f018e942ffa15103d4d3da278d2ee08892350b606c5262`.

Scope is these1.x InfluxQL/auth/path branches.2.x/3.x, Flux, TLS, clustering,
arbitrary write/admin queries and every retention policy remain unqualified.
Native anonymous refusal is separate from required-option validation; no invented
anonymous module run is claimed.
