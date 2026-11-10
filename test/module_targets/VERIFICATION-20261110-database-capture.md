# Database capture and integrated checkpoint, November 10

This retained checkpoint precedes the
[148-module FileServer checkpoint](VERIFICATION-20261110-fileserver.md).

Current input hashes, exact passing counts and owned teardown establish
**147 runtime modules, 75 families and 1,031 functional cases**. This adds
`auxiliary/server/capture/mysql` and `auxiliary/server/capture/mssql` to the
retained [145-module checkpoint](VERIFICATION-20261110-nfs-reader.md). It is a
selection of qualifying retained runs, not a full RSpec run or repository-wide
completion. WordPress remains excluded; its failures and the separate Ansible
deployer investigation remain in the [deferred index](DEFERRED.md).

The [shared target guide](database_capture/README.md) records the pinned genuine
clients/servers, independent wire controls, credentials, reporting and limits.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb capture_mysql capture_mssql
bundle exec rspec spec/modules/auxiliary/server/capture
```

## Final results

Invocation `20261110T041457-7d3925` completes naturally:

| Profile | Cases | Failures | RSpec seconds | Current inputs |
| --- | ---: | ---: | ---: | ---: |
| `capture_mysql` | 17 | 0 | 202.543895 | 50 |
| `capture_mssql` | 12 | 0 | 107.563702 | 51 |

Both profiles have zero pending/outside-example errors and passed teardown.
The parent copied and byte-checked the complete 474-file invocation, preserving
its original revision, paths, commands and isolated metadata snapshots. Every
recorded runtime input is current; all 70 sealed source/documentation files also
match. Independent exact-project checks confirm both runner projects and their
four recorded volumes absent. The worker audits all 13 native/runner projects
and 27 recorded volumes absent; an earlier auto-removed package-query container's
anonymous volume names were not recorded for separate inspection.

Native gates pass 43 CLI controls and 32 actual PCAPs. Then 54 real client
programs/PCAPs exercise actual Framework passive jobs, including same-port job
restart and repeat. All 86 packet-capture controllers succeed. Direct SQL checks
25 complete credential graphs: 19 nonreplayable hashes, four passwords and two
blank passwords, exact bytes/type/format, actual listener/service/module origin,
client address and workspace identity. All remain UNTRIED without a validation
timestamp. Eighteen John files contain 36 exact lines. Capture does not establish
a validated target login; the installed model has no persisted login-proof column.

## Native proof and owning repairs

Oracle MySQL 8.0.36 and MariaDB 11.2.2 clients authenticate against both genuine
servers. Native controls cover spaces, punctuation, empty/rejected passwords,
two fixed binary-response boundary passwords and independently recomputed SHA1
challenge responses. Their normal native TLS negotiation is distinguished from
Framework's observed non-TLS capabilities; required TLS must disclose no password.

SQL Server 2019 build 15.0.4500.2 accepts real FreeTDS 1.3.17 TDS 7.1/7.4 SQL
logins, including explicitly policy-disabled empty-password accounts. Actual
LOGIN7 decoding matches fixture bytes. DOMAIN\\user emits genuine NTLM Type1
but the real SQL server rejects an untrusted domain without AD. Capture NTLM
responses are independently cryptographically verified, not claimed as validated
domain authentication. Selected TDS paths explicitly disable encryption.

Three separate source repairs address observed owner failures:

| Module/path | Change |
| --- | --- |
| MySQL native response | Preserve all twenty binary bytes, including trailing NUL/space. |
| MySQL challenge option | Accept exactly forty hex characters including zero; correct twenty-byte wording. |
| MSSQL SQL LOGIN7 | Store an empty password as an empty string rather than literal `<empty>`. |
| MSSQL NTLM | Bind the existing extended-session option, retain both LM/NT response fields, and report the actual MSSQL listener port/service. |

Identical focused inputs reproduce **34/14 → 34/6 → 34/3 → 34/0**, changing only
the appropriate owning source per step. This count includes seven shared
formatter examples. The related capture folder reproduces **77/14 → 77/0**,
including all 50 existing examples. The parent independently passes all 77 in
2.773297 seconds. Six changed Ruby files lint clean. Module tidy retains its
existing informational notice; MySQL guide tidy retains seven inherited warnings
and byte-identical human Scenarios. No shared stream, parser, model, transport,
lifecycle, runner or project dependency changed.

## Preserved failures and observer corrections

| Invocation | MySQL | MSSQL | Meaning |
| --- | --- | --- | --- |
| `20261110T030643-6f1268` | 17/7 | 12/7 | Fixture constant/early SQL observations mixed with owner failures. |
| `20261110T031737-37a503` | 17/6 | 12/7 | Constant/cardinality corrected; passive refusal still observed too early. |
| `20261110T033357-d24d13` | 17/5 | 12/6 | Strict original baseline leaves eleven owning failures. |
| `20261110T040012-4f069f` | 17/1 | 12/0 | Repaired owners; one credential core observed without completed joins. |
| `20261110T041457-7d3925` | 17/0 | 12/0 | Same owners with bounded structural credential readiness. |

The harness corrections use actual background-job refusal/termination, safe
profile selection during excluded discovery and complete joined-row readiness.
The final predicate uses the existing ten-second bound; exact value, identity,
status and John assertions remain outside the poll. The earlier partial core
observation and failed post-terminal SQL attempt remain retained. The final run
observes zero rows then a complete core graph, not a same-core partial-to-complete
transition. It proves the stronger observer works; no unobserved causal transition
or model/lifecycle defect is claimed. The final harness delta is explicit, not
presented as a source-only runtime comparison.

One failed early native empty-auth decoder PCAP was overwritten before the first
checkpoint. Its failure log, decoded fields and partial inspection survive; no
reconstructed bytes are called recovered wire. All later native and owning-failure
PCAPs remain complete. No module verdict relies on that early attempt.

## Durable evidence and limits

The unchanged worker export is
`/Users/dwelch/.codex/reports/database-capture-validation-20261110-7385b0df1d8f`.
The parent re-read all 3,296 entries in `checksums.sha256`; its SHA-256 is
`ae62647f6c50d25491472bf70bf64fae63ee8dd67ef4a4e9bd1412962841147d`.
It retains all five invocations, actual wire/SQL/schema data, native failures,
source-only unit comparisons, input freezes, cleanup and separate source/lab
commits. Raw evidence remains outside Git.

Parent units/lint/discovery, source/export/import/resource checks, complete
current selection and inventory are sealed separately at
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-966276147bc`.
All 22 checksum entries were re-read; `SHA256SUMS.json` SHA-256 is
`b6be1b2277c483f25cf0e83fad13f3fd837bb9966781f08160d5b5d3cfb6987f`.
Acceptance-excluded discovery passes seven ancillary examples without outside
errors. The prior pushed checkpoint's Verify matrix remains pending in these
receipts; no full-suite CI success is inferred.

This does not qualify complete protocol conformance, fragmented/coalesced or
oversized logins, multiple-user concurrency/deduplication, other auth plugins,
NTLM empty secrets, AD/Kerberos, Unicode boundaries, IPv6 or TLS capture listeners.
The static queue still has 5,179 source files including components/support code,
148 registered sources (147 qualified plus WordPress) and 5,019 pending individual
reviews. FileServer, SIP and Gitea qualification continues separately. Remaining
targets and paths need individual evidence; this checkpoint leaves the goal active.
