# NiFi processor and integrated checkpoint, November 10

Current hashes, exact passing counts and owned teardown establish **154 runtime
modules, 85 families and 1,135 functional cases**. The unchanged processor module
adds 19 cases to the [Hadoop checkpoint](VERIFICATION-20261110-hadoop.md).
The full campaign remains incomplete; retained failures stay in the
[deferred index](DEFERRED.md).

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb nifi_processor_legacy nifi_processor_vulnerable nifi_processor_fixed
```

The three guides describe official digest-pinned NiFi 1.13.2 HTTP/no-auth and
1.21.0/1.22.0 authenticated HTTPS, one release per fresh project, with genuine
Apache controls. Native UI/API/version/authentication, identity, repeated actual
ExecuteProcess commands and a preserved GetHTTP canary precede module execution.
The ordinary module DELAY remains 5. Processor execution is a legitimate feature
on the H2-fixed release; this is not an H2 vulnerability comparison.

| Stock release | Cases/failures | RSpec seconds | Current inputs |
| --- | ---: | ---: | ---: |
| 1.13.2 |6/0|179.151173|81|
| 1.21.0 |9/0|132.894461|81|
| 1.22.0 |4/0|81.006388|81|

Final invocation `20261110T074301-bed95b` terminates naturally with zero pending
or outside errors and successful cleanup. The selected union has 87 current
files. Owning source remains
`19b266b19c7cd3f6ee32a8b4b926f3c7cd7eec3b30c4d16ddad61044aeb5f83a`.
No production, shared runner, SDK, project dependency or timeout changes.

## Meaningful outcomes and attribution

There are 38 public module calls, ten opened AND used reverse-Bash shells and
six additional exact generic-command proofs as UID 1000. Native controls record
135 CLI/388 HTTP operations, plus 83 separate proof CLI operations. Exact API
graphs/configuration survive each case and repetition. The real stopped GetHTTP
canary authenticates to Apache before and after, with actual 200/304 responses
and its original URL restored. No error-path operator graph restoration occurs.

Valid bearer authentication is independently observed in the actual execution
replicant datastore and standard Authorization trace. An invalid bearer receives
401 despite valid fallback credentials. Missing/wrong credentials, missing paths
and unrelated Apache do not mutate the graph. Linux Fetch is deliberately tested
as an incompatible payload rejection twice; the Unix target metadata is preserved.
It does not count as successful Fetch delivery.

The original 77-key corpus has 13 observer-induced failures/cascades because a
passive observer lacks the GeneralEventSubscriber no-op interface. A real-dispatcher
control reproduces and repairs that fixture contract. The 78-key replay has
6/0, 9/3 and 4/0: positional assignments do not accept the hyphenated BEARER-TOKEN
name, and the chosen Linux Fetch adapter is incompatible with the Unix target.
The final fixture uses public `run -o BEARER-TOKEN=value` and explicit repeated
Fetch refusal. These are fixture/corpus corrections, not owning repairs or a
source-only before/after claim. All original bytes/results are preserved.

Two earlier native multi-release starts miss readiness before module execution.
Measured per-release native startup passes the unchanged limit with stock
resources; the shared scanner profile and all 55 recorded inputs remain exact.
No setup failure is called a module defect.

## Evidence, checks and limits

Parent byte-checks all 291 final invocation files, preserving actual revision,
paths, commands, read prompt/isolated BOOT and fresh parsed metadata. All 1,478
worker checksum entries and 87 current source files match the immutable export:
`/Users/dwelch/.codex/reports/nifi-processor-20261110-fc923f79990`.
SHA256SUMS.json SHA-256 is
`b9f2ba034541afbdb44a011023a9e08118f61bdea4c90cc15e83484d46dafd3b`.

Parent inspection finds 99 recorded runtime objects absent across three
invocations (final 9 containers/3 networks/21 anonymous volumes), plus 51 known
native-preparation records and ten native-gate identities. The first native setup
failure lacks original container/volume IDs; retained name/project absence does
not establish unseen identities. That gap remains explicit.

Parent lint passes the new Ruby spec; selected dry discovery passes 6/9/4 and
excluded discovery passes seven ancillary examples. Docs retain exactly two
inherited warnings, identical normalized diagnostics and the entire original
human prefix/Scenarios. No full local RSpec suite was run. Parent checks are
sealed in 21 entries at
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-941474f13f7`,
manifest SHA-256
`49e5b2fd81f40b906e65ee5a24baf5d3f90602ab433b2ae251aa28814ed7da35`.

Qualified scope is Unix generic commands/reverse-Bash on these releases and
chosen auth modes, with local self-signed certificate verification disabled.
Windows, Linux Fetch, other payload branches, clustered NiFi and full TLS remain
unqualified. H2, both credential-gathering session types, SIP, Spark and Druid
continue separately.
