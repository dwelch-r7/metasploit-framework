# NiFi scanners and integrated checkpoint, November 10

Current inputs, exact passing counts and owned teardown establish
**150 runtime modules, 77 families and 1,055 functional cases**. This adds the
two existing NiFi version/login scanners to the retained
[148-module checkpoint](VERIFICATION-20261110-fileserver.md). Neither production
module changed. The repository-wide goal remains incomplete; retained WordPress
and Ansible deployer failures remain in the [deferred index](DEFERRED.md).

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb nifi_discovery
```

The [target guide](nifi_discovery/README.md) describes official digest-pinned
Linux amd64 NiFi 1.13.2 HTTP, 1.21.0/1.22.0 self-signed HTTPS, genuine unrelated
Apache HTTP, public fixture credentials and ephemeral reporting PostgreSQL.
Independent native gates verify real UI/API versions, accepted/rejected login,
authenticated identity, UID/Java and error-page behavior before module execution.

## Results and attribution

| Invocation | Result | RSpec seconds | Meaning |
| --- | --- | ---: | --- |
| `20261110T052427-52f6ab` | Setup failed | — | Legacy release misses readiness; no console/RSpec/module dispatch. |
| `20261110T053933-329e49` | 15/3 | 92.989939 | Three correct negative outputs rejected by fixture helper. |
| `20261110T054937-24c8fd` | 15/0 | 98.885635 | Same original modules; expected negative-print allowance corrected. |

All finish naturally and pass teardown. The final run has zero pending or
outside-example errors and 31 actual auxiliary run commands. Fresh native
controls pass six CLI operations and 25 HTTP requests. Repeated genuine logins
persist exact complete credential/service/origin/workspace graphs, account
bytes/type, SUCCESSFUL status and validation timestamp. Repeats deduplicate;
separate workspaces remain isolated. HTTP login refusal, the unauthenticated
legacy instance, unrelated content and missing application paths create no
successful credentials. Actual response proof remains external; no nonexistent
persisted login-proof column is invented.

The original readiness failure is local setup, not a module verdict. Changing
only the legacy CPU quota from two to four lets the same six-service native
stack meet the unchanged 120-second readiness gate in 106.699953 seconds, then
pass native controls. Images, heap, health predicate and shared runner stay
unchanged. This is a measured configuration, not a startup-time guarantee.

The first full corpus passes twelve cases. In the other three, the scanner
correctly prints "not detected" for a genuine branded HTTP 200 error page, but
the test helper's default ban on `[-]` fails first. The final spec changes only
the local expected-error allowance. All substantive assertions, module/library,
native and target bytes remain unchanged. No failing case is called a module
defect. NiFi's missing path has a browser meta-refresh, not an HTTP redirect;
the native parser establishes that no namespace script exists there.

## Evidence and limits

All 55 recorded inputs are current. The parent copies and byte-checks the
complete 54-file final invocation, preserving revision, paths, commands and
actual isolated prompt/BOOT plus both parsed atomic metadata snapshots.
Independent parent inspection confirms six final containers, their network and
22 recorded volumes absent. Worker audits cover all three runner generations
and 66 recorded volumes, plus the separate four-container/21-volume native
prototype and six-container/22-volume readiness benchmark. All are absent.

The unchanged export is
`/Users/dwelch/.codex/reports/nifi-discovery-20261110-4fb1962d08f`.
The parent re-read all 535 entries in `SHA256SUMS.json`; its SHA-256 is
`b961f84f4e6082efa9c234d4672ebd3b9cff027fe1b43f254f6345117fd19d85`.
It includes native setup/observer failures, captured files, before/final freezes,
all three runs, source and cleanup. No prior evidence is rewritten.

Parent lint passes the new Ruby spec, and acceptance-excluded discovery passes
seven ancillary examples without outside errors. Selected dry discovery passes
15 examples. Both changed module guides pass tidy and preserve human Scenarios.
No full local RSpec suite was run. Parent import/export/source/resource checks,
lint/discovery, inventory and selection are sealed at
`/Users/dwelch/.codex/reports/module-target-parent-validation-20261110-aafedae0c96`.
All 11 checksum entries were re-read; manifest SHA-256 is
`809981f856f64f5b3fd77f0d82fada1e00cd1974a51ac34a716ce1a3f8c34a17`.

This qualifies the specified scanner paths, self-signed TLS with certificate
verification disabled, configured VHOST, repeated reporting and workspace
isolation. Windows, IPv6, LDAP/OIDC/client certificates, other versions, every
brute-force option and full TLS behavior remain unqualified. Native processor,
H2 and encrypted-file proofs establish feasibility only; their Framework modules
and both credential-gathering session types are continuing separately. The queue
still has 5,179 source files including components/support code, 151 registered
sources (150 qualified plus WordPress), and 5,016 pending individual reviews.
