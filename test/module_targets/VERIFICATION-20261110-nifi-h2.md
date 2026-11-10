# NiFi H2 and integrated checkpoint, November 10

Current input hashes, exact counts and owned teardown establish **165 runtime
modules, 95 families and 1,233 functional cases**. H2 adds13 cases to the
[InfluxDB checkpoint](VERIFICATION-20261110-influxdb.md). The shared state-helper
repair also refreshes15 scanner and19 processor cases; those34 are counted once.
The full campaign remains incomplete.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb nifi_h2_legacy nifi_h2_vulnerable nifi_h2_fixed nifi_discovery nifi_processor_legacy nifi_processor_vulnerable nifi_processor_fixed
```

Digest-pinned stock NiFi1.13.2,1.21.0 and1.22.0 run as native UID1000, with real
Apache controls. Independent vendor CLI/HTTP controls establish actual versions,
authentication, installed H2 JARs, file-URL execution on affected releases and the
fixed release's JDBC-scheme refusal. Local self-signed TLS verification is
disabled; trusted TLS is outside this qualification.

| Family | Raw invocation | Cases/failures | RSpec seconds |
| --- | --- | ---: | ---: |
| H2 legacy |20261110T095332-be1aab|4/0|237.849152|
| H2 affected |same|6/0|220.576216|
| H2 fixed |same|3/0|37.064499|
| Scanner |same|15/0|48.878593|
| Processor legacy |20261110T091845-b54df5|6/0|127.288844|
| Processor affected |same|9/0|134.092893|
| Processor fixed |same|4/0|81.701888|

These are47 current passing cases from two complete recorded invocations, with
zero pending/outside errors and passing cleanup. Both used runtime revision
d641401f0d5; the subsequent lab commit preserves identical selected bytes.
Parent verifies all120 union inputs and all914 imported invocation files.

H2's26 public calls opened24 shells, used four distinct shells for independent
target proofs and closed all24. Processor19 opened/used/closed ten more. Scanner31
public calls verify real credential persistence/workspace isolation with SQL.
Repeated checks, commands, auth refusals, bearer/password modes, missing paths,
fixed-version forced attempts and exact component graph restoration are covered.
The final28 native gate records H2 176CLI/362HTTP plus55 separate CLI receipts;
scanner6CLI/25HTTP plus40 SQL/CLI receipts. The stopped GetHTTP canary is preserved
and independently replayed. H2 file-database paths, UID and hashes are recorded
before explicit operator removal; automatic module file cleanup is not claimed.

Four cohesive commits repair rejected DTO fields/toolkit directory handling,
cleanup revision/error handling, shared controller state bodies, and add the lab.
Native one-field controls identify six rejected DTO fields; the original revision0
with its original clientId is accepted. A different-client revision hypothesis
was disproved. Both state directions reject uiOnly:true with400/no change;
omitting that sole field accepts200 and reaches ENABLED/DISABLED twice. Public
helper signatures, successnil and typed errors remain unchanged. These native
DTO probes replay actual method emissions, rather than claiming wire captures.

Original corrected H2 passes11/13; owner repairs still expose the shared state
failure. Repairing the helper leaves one legacy quick-command fixture failure.
Two native two-second trials produce no proof/taskCount0, including bounded
post-removal observation; two thirty-second trials produce genuine UID1000
proofs/taskCount20/21. A200 start can precede actual pool readiness. The fixture
uses ordinary public DELAY30 for legacy generic commands without changing source,
shared runner or timeout. Final H2 passes13/0. The earlier mixed invocation
actually runs32/1; scanner misses up--wait120 before any native/BOOT/RSpec call,
then passes15/0 with the same bound and inputs. Both histories remain preserved.

Matched source-only focused comparisons pass21/10→21/0 for owner behavior and
23/4→23/0 for the library. The combined count is37/0 after counting seven shared
examples once; parent independently passes37/0. A source-raced supplemental run is
excluded. Parent's initial explicit-child require causes an outside-example boot
error; requiring the parent namespace fixes only the bootstrap. All diagnostics
remain separate from module verdicts.

Parent lint confirms zero new offenses, retaining one owner default-payload and
one library documentation offense. Actual module msftidy retains status2 for that
same inherited owner offense. Docs pass with all4,474 original human-written
bytes unchanged. Selected dry discovery4/6/3/15 and excluded7 pass; no full local
RSpec suite was run.

Parent verifies all2,805 worker checksum entries at
`/Users/dwelch/.codex/reports/nifi-h2-20261110-e3f7f683f32`;
SHA256SUMS SHA-256
`16fac05e9dde26688c023ef1ae2b4f5b252662aea9932d9299b532a0df1cc7b6`.
All187 exact parent object checks pass:45 container IDs,14 network IDs and128
volumes are absent across the two invocations and three native counterfactual
projects. Parent receipts:
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-29ed583efb3`,
40 entries, manifest SHA-256
`5d72e7f2fd55420e5d3d3ed47a6656714ea9a0265213a9ae72849931cb1fe8a3`.

Other platforms/layouts/releases, additional payload families and auth policies
remain unqualified. The [deferred index](DEFERRED.md) retains unresolved modules.
