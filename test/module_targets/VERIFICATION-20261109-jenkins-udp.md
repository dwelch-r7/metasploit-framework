# Jenkins, UDP and Elasticsearch qualification

The current verified checkpoint covers **94 production runtime modules, 36
families and 498 functional cases**. Every selected result has its exact expected
count, zero failures/pending/outside-example errors, matching current recorded
input hashes and successful owned teardown. A fresh thirty-family invocation
passes all 402 cases; separate current-input HTTP, Jenkins, TFTP, NTP,
Jenkins-command and Elasticsearch results complete the registered set.

This qualifies the documented profiles, not every platform, version or option
of those modules. The repository-wide campaign remains active: most source
modules still await individual feasibility review and functional qualification.
No pull request was created and no full local repository RSpec suite was run.

## Repository layout and qualified targets

Reusable targets live under `test/module_targets/<family>/`, with Compose,
configuration/source, a manifest, independent native controls and a lab guide.
Module documents link to the shared definitions. Acceptance cases live under
`spec/acceptance/module_targets/`; focused owning regressions and their real
captures live under `spec/modules/` and `spec/file_fixtures/`.

The runner creates a fresh project and Framework configuration, publishes only
random loopback ports, retains image identities, native commands, console logs,
loot, RSpec JSON and input digests, and removes owned resources. Its shared
console mounts current source read-only and exposes no host listener. UDP-only
ports now have an explicit protocol mapping; legacy integer TCP definitions
retain their endpoint shape. A failing native preflight or assertion cannot
qualify a family.

| New profile | Real target and independent controls | Final parent cases |
|---|---|---:|
| Jenkins | Digest-pinned weekly 2.441/2.442, LTS 2.426.2/2.426.3 and open 2.442; separate official CLI client, actual files, Groovy, HTTP policies and server JVM properties | 51 |
| TFTP | Pinned Ubuntu 22.04 tftpd-hpa/tftp-hpa 5.2; native octet/netascii byte comparisons and actual read permission, plus unrelated BIND | 6 |
| NTP | Pinned Ubuntu ntpd/ntpq 4.2.8p15; native v2/v3/v4 properties, refused queries and independent UDP payloads, plus unrelated BIND | 6 |
| Jenkins command scanner | Existing open/secured Jenkins 2.442 and actual Apache; native process output, CSRF cookie boundary and file-owner proof | 8 |
| Elasticsearch | Vendor digest-pinned 7.9.1 with native security off/on; seeded records, exact search samples, actual users/roles and HTTP permission controls, plus Apache | 11 |

All target credentials and data are public disposable fixtures. No production
service, existing home directory or host Docker socket is used. NTP has no peers
or external clock sources, disables time/frequency and kernel discipline, and
explicitly lacks SYS_TIME. Its probes are ordinary single requests; SRCIP is
omitted. Native TFTP full transfers run inside the owned namespace because its
data socket uses a separate transfer port; complete host-NAT transfer is not
claimed. Independent host probes verify the actual UDP port mapping.

## Reproduced module faults and separate repairs

Each owning pair below preserves its cases and native inputs apart from the
production module. Counts are total examples/failures. Subsets overlap the final
parent suites and must not be added to the 498 functional cases.

| Owning module | Parent repair | Matched native before → after |
|---|---|---|
| `auxiliary/gather/jenkins_cli_ampersand_arbitrary_file_read` | `ef81d66f438` | 22/10 → 22/0 |
| `auxiliary/scanner/http/jenkins_enum` | `dc6eb2429f7` | 6/1 → 6/0 |
| `exploit/multi/http/jenkins_script_console` | `c5e5d667a18` | 17/14 → 17/0 |
| `auxiliary/scanner/ntp/ntp_readvar` | `f938927d7b7` | 6/1 → 6/0 |
| `auxiliary/scanner/http/jenkins_command` | `a9e6e553812` | 7/6 → 7/0 |
| `auxiliary/gather/elasticsearch_enum` | `21bcd522181` | 11/7 → 11/0 |

The Jenkins CLI module interpreted binary framing as text, corrupting loot, and
used one-byte/character lengths that failed on long paths. Forced patched targets
could be reported as disclosing the literal unexpanded argument. The repair uses
Java modified UTF, complete frame lengths/decoding and exit-status validation,
rejects patched echoes and propagates request-thread failures. Genuine JDK
reference bytes and network captures support the boundaries. Its interim two
Unicode failures were investigated as binary-tagged console paths compared with
decoded UTF-8; local normalization preserves datastore bytes and encoding.

Enumeration parsed modern HTML as XML and mishandled hidden value controls.
The repair uses the existing HTML helper and row-local displayed values,
preserving String callers and reporting shape. Native server `jcmd` properties
and the actual OS account establish the printed data independently.

Script-console execution lacked the standard cleanup override, omitted Bourne
from registered Linux flavors and suppressed parent session bookkeeping through
a dead callback. It also lost the anonymous session cookie associated with a
CSRF crumb. FileDropper, explicit Bourne metadata and the inherited session hook
restore those contracts. Keeping the same native crumb returns HTTP 403 without
its JSESSIONID and HTTP 200 with it. Password/token/open commands, Linux x86/x64
delivery and repeated real command-shell/Meterpreter sessions now pass with
target proof. Session cases check automatic stager cleanup; non-session command
effects have explicit operator cleanup.

NTP accepted an actual twelve-byte DNS FORMERR as an NTP service with empty
information. The repair validates complete control headers, successful reply
flags, version/opcode/sequence and bounded data before reporting. Real reply
padding and unsynchronized-clock bits remain accepted and counted. The observer
retains arguments while preserving original reporting calls; this establishes
gathered information and emitted reports, not database storage.

The additional Jenkins command scanner missed modern crumb/session fields and
misclassified secured controllers. Native original-versus-candidate requests also
establish quote compilation errors and literal entity/marker corruption. The
repair reads actual OS values, preserves the CSRF session, escapes Groovy strings
and uses genuine scriptText JSON results to preserve stdout/stderr and concise
process failures. Existing Linux String.execute tokenization and the one-second
process bound remain; no shell semantics are added. Parent case eight adds real
console Unicode/dollar output beyond the matched seven-case worker pair.

Elasticsearch's table CSV conversion changed actual newlines to spaces. Actual
HTTP 403, zero-row and unrelated-HTML paths also caused nil parser exceptions.
The repair uses the existing CSV dependency for literal fields, validates
required/optional HTTP and JSON replies, and handles missing source hits. An
additional captured-Hash regression repairs a nil emitted index-note name;
persisted storage remains unqualified. Public loot identifiers stay compatible.
DOWNLOADROWS retains the existing bounded initial query, with an accurate maximum
row description, and the standard port default stays 9200.

## Fixture corrections and focused verification

Failures were classified using native evidence before changing modules. Genuine
Jenkins HTTP 401 challenges need not include a version header; that original
native expectation was corrected. Three no-session authentication negatives
needed explicit AllowNoCleanup consent to reach authentication. NTP's first
attempt stopped in observer setup because it used a host-only path. TFTP's
native client returns a real permission error different from the initially
expected wording. These are setup/assertion corrections, not module faults.

Elasticsearch's first matcher assumed CSV row order and its scoped role lacked
index-monitor permission. Rows now compare as a set with exact field values;
native scoped node/index requests verify the intended permission. The corrected
unchanged-source baseline still fails seven cases: four literal-newline losses
and three parser exceptions. No value or meaningful negative assertion was
relaxed to make a module pass.

Final owning unit corpora pass: CLI 43/0, enumeration 19/0, script console 20/0,
NTP 28/0, command scanner 33/0 and Elasticsearch 28/0. Each separate total
contains seven pre-existing support examples, so they must not be summed as new
independent coverage. Parent CLI/script validation passed 56/0 together, with
the other owning files also passing independently. No full local suite ran.
New specs/lab files have no lint offenses. Enumeration retains 81 inherited
source findings, script console four, NTP four and command scanner thirteen,
with none added; CLI and Elasticsearch have none. Module tidy passes with
existing legacy/no-CVE notices where applicable. The four Jenkins documents
retain 34 inherited diagnostics, TFTP six, and Elasticsearch none. Existing
human-written Scenarios are preserved.

## Limits, evidence and CI

These passes cover the stated Linux/container releases, protocols and paths.
Windows, other versions, TLS/proxies/contexts where not explicitly tested,
restricted Jenkins roles and other delivery families remain unqualified. The
CLI reads the first two exposed text lines; arbitrary binary fidelity and other
locales/encodings are not established. A legitimate lone line exactly matching
`@<requested path>` is conservatively rejected as indistinguishable from a
patched echo. NTP IPv6/authentication/Mode 7/native larger fragments and time
synchronization remain unqualified. Elasticsearch uses flat consistent source
fields; heterogeneous/nested schemas and source-disabled indices are unqualified.
No new profile establishes persisted database behavior.

Recoverable source-only pairs, raw native results, diagnostic definitions and
checksum inventories are retained under `/Users/dwelch/.codex/reports/`:

- `jenkins-cli-file-framing-20261109-7e2c5c7765d/`
- `jenkins-enumeration-html-20261109-030361f613a/`
- `jenkins-script-console-paths-20261109-6034a783776/`
- `ntp-readvar-reply-validation-20261109-e57cff02cc9/`
- `jenkins-command-console-20261109-4d734de67a7/`
- `elasticsearch-enumeration-data-20261109-0439a4385b8/`

At earlier published revision `e16b4bc4157`, lint and all eight acceptance
workflows, including Meterpreter/Mettle, passed. Verify failed at
`cert_request.rb:251` resolving `ms-ntds-sec-ext` through OpenSSL ASN.1 ObjectId
on Ruby 3.4.12. Its owning source/spec are unchanged from the campaign base,
but no complete baseline execution establishes attribution. The earlier
Meterpreter stalls remain unclassified despite a later passing workflow.
Those results do not establish current-head CI success; the new publication
requires its own workflow inspection.

## Current source verification matrix

RSpec durations below include console startup and native controls within the
suite, and exclude image preparation. They are not per-module timing claims.
The evidence paths are relative to the repository root. Every row was selected
only after checking exact counts, zero pending/outside errors, current recorded
SHA-256 inputs and owned teardown.

| Family | Cases | RSpec seconds | Evidence |
|---|---:|---:|---|
| apache_normalize_path | 16 | 41.77 | `tmp/module-target-tests/20261109T143602-89d864/apache_normalize_path/` |
| axis2 | 12 | 186.32 | `tmp/module-target-tests/20261109T143602-89d864/axis2/` |
| couchdb | 8 | 38.25 | `tmp/module-target-tests/20261109T143602-89d864/couchdb/` |
| couchdb_exec | 9 | 243.00 | `tmp/module-target-tests/20261109T143602-89d864/couchdb_exec/` |
| couchdb_legacy | 9 | 14.38 | `tmp/module-target-tests/20261109T143602-89d864/couchdb_legacy/` |
| dns | 28 | 146.20 | `tmp/module-target-tests/20261109T143602-89d864/dns/` |
| elasticsearch | 11 | 53.44 | `tmp/module-target-tests/20261109T152330-517255/elasticsearch/` |
| ftp | 13 | 73.65 | `tmp/module-target-tests/20261109T143602-89d864/ftp/` |
| http | 14 | 56.80 | `tmp/module-target-tests/20261109T142833-bf0fc5/http/` |
| jenkins | 51 | 353.93 | `tmp/module-target-tests/20261109T143705-1f597e/jenkins/` |
| jenkins_command | 8 | 93.27 | `tmp/module-target-tests/20261109T151223-9835bb/jenkins_command/` |
| ldap | 10 | 18.51 | `tmp/module-target-tests/20261109T143602-89d864/ldap/` |
| linux_post | 8 | 183.30 | `tmp/module-target-tests/20261109T143602-89d864/linux_post/` |
| linux_system | 12 | 421.91 | `tmp/module-target-tests/20261109T143602-89d864/linux_system/` |
| mail | 13 | 107.13 | `tmp/module-target-tests/20261109T143602-89d864/mail/` |
| mariadb | 10 | 16.91 | `tmp/module-target-tests/20261109T143602-89d864/mariadb/` |
| memcached | 4 | 41.08 | `tmp/module-target-tests/20261109T143602-89d864/memcached/` |
| mongobleed | 11 | 45.72 | `tmp/module-target-tests/20261109T143602-89d864/mongobleed/` |
| mongodb | 31 | 70.71 | `tmp/module-target-tests/20261109T143602-89d864/mongodb/` |
| mongodb_legacy | 12 | 16.47 | `tmp/module-target-tests/20261109T143602-89d864/mongodb_legacy/` |
| mqtt | 10 | 39.55 | `tmp/module-target-tests/20261109T143602-89d864/mqtt/` |
| mssql2019 | 15 | 68.33 | `tmp/module-target-tests/20261109T143602-89d864/mssql2019/` |
| mssql2022 | 15 | 32.32 | `tmp/module-target-tests/20261109T143602-89d864/mssql2022/` |
| mysql8 | 10 | 19.40 | `tmp/module-target-tests/20261109T143602-89d864/mysql8/` |
| ntp | 6 | 36.89 | `tmp/module-target-tests/20261109T150045-2bb9a0/ntp/` |
| postgres | 9 | 17.21 | `tmp/module-target-tests/20261109T143602-89d864/postgres/` |
| redis | 22 | 117.22 | `tmp/module-target-tests/20261109T143602-89d864/redis/` |
| rsync | 6 | 21.85 | `tmp/module-target-tests/20261109T143602-89d864/rsync/` |
| smb | 20 | 56.14 | `tmp/module-target-tests/20261109T143602-89d864/smb/` |
| smtp | 9 | 33.09 | `tmp/module-target-tests/20261109T143602-89d864/smtp/` |
| snmp | 22 | 57.04 | `tmp/module-target-tests/20261109T143602-89d864/snmp/` |
| ssh | 2 | 18.44 | `tmp/module-target-tests/20261109T143602-89d864/ssh/` |
| tftp | 6 | 62.21 | `tmp/module-target-tests/20261109T141732-e65fed/tftp/` |
| tomcat | 14 | 133.64 | `tmp/module-target-tests/20261109T143602-89d864/tomcat/` |
| vnc | 20 | 88.60 | `tmp/module-target-tests/20261109T143602-89d864/vnc/` |
| webdav | 22 | 152.65 | `tmp/module-target-tests/20261109T143602-89d864/webdav/` |

The thirty-family invocation is `20261109T143602-89d864`; its terminal
`summary.json` reports all thirty passing. The shared Elasticsearch/NTP
invocation `20261109T150045-2bb9a0` remains a failed invocation because its
unchanged-source Elasticsearch baseline failed, despite its independently
passing NTP family. No failed or superseded result is counted in this matrix.

A read-only review of the runner, owning fixes, native controls, captures and
acceptance assertions found no unresolved material finding in the qualified
paths. Remaining concerns are the explicit profile limits and the separate CI
Verify exception. Completed fix-worktree evidence exports were checksum-checked;
checkouts remain intact where the app still reports active-task ownership.
