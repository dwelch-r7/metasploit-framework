# Ansible, Joomla and credential-reporting qualification

The selected checkpoint covers **104 production runtime modules, 44 families
and 629 functional cases**. Every selected result has its exact expected count,
zero failures/pending/outside-example errors, matching current recorded input
hashes and successful owned teardown. Relative to the
[preceding checkpoint](VERIFICATION-20261109-proxy-history.md), this adds two
modules and three target profiles. The credential profile extends three already
counted login modules. The repository-wide campaign remains active. No pull
request was created or full local repository RSpec suite run.

## Reusable targets and controls

| Family | Independent controls and meaningful coverage | Cases |
|---|---|---:|
| [Ansible controller collection](ansible/README.md) | Real Ubuntu 22.04 controller/node, ansible-core 2.12.0, native SSH/Ansible, actual inventory/config/key bytes; root/nonroot shell and Meterpreter sessions | 14 |
| [Joomla API](joomla_api/README.md) | Official 4.2.7/4.2.8 application code, database/user/configuration checks, native authenticated/anonymous/refused API requests, root/subdirectory/hidden-metadata profiles | 12 |
| [Credential reporting](credential_reporting/README.md) | Genuine PostgreSQL, SSH and Apache authentication, disposable migrated Framework database, independent SQL and native reuse of a recovered SSH key | 11 |

Targets use pinned images/source, random loopback ports and owned networks.
Reverse handlers remain inside the project. No Docker socket or existing
operator database is used. Existing human-written module Scenarios remain
unchanged; module documentation links to these reusable target definitions.

Ansible native controls verify both controller identities, valid/rejected SSH,
compact INI, readable/protected keys and four real copy/execute/remove playbooks.
Every module example creates a fresh proven session. Cases check exact JSON
inventory, configuration and private-key loot, selected/all hosts, denied reads
and a restored empty inventory. They explicitly select `/usr/bin/ansible` and
`/usr/bin/ansible-inventory`; default executable discovery remains unqualified.

Joomla native controls perform 78 operations before module assertions. Valid
administrator API access works on both releases; anonymous, wrong-password and
limited-user requests establish actual policy. The vulnerable public-query path
works only on affected targets. Exact user/configuration loot, real filtered
empty lists and plugin disable/restore paths are checked. Actual router source
hashes establish the version boundary independently of advertised metadata.
Administrator authentication changes last-visit timestamps legitimately; each
run compares loot with its own native captures.

The credential profile starts with an empty Framework schema and uses ordinary
`db_connect` migrations. Direct SQL checks credential/public/private/core/origin,
login, host, service and workspace rows. Repeated passwords/keys must not create
duplicates, incorrect passwords must not become successful logins, password/key
records for one account stay distinct, and workspace/service relationships stay
correct. A stored SSH key recovered through SQL must authenticate through native
OpenSSH. Real `creds` CSV export is also checked. The migrated schema has no
login-proof column; authentication captures remain run artifacts.

## Failure classification and repairs

Ansible's original functional run had **14 failures in 14 cases**, with native
controls and teardown passing. Captures established inventory stored in Ruby
notation instead of JSON, ignored HOSTS, genuine `UNREACHABLE!:` results omitted
by parsing, a compact INI `nil.strip` error and unreadable keys saved as empty
successful loot. Separate helper/module repairs retain operation-specific
failures and the existing helper return shape. The final functional run passes
**14/0**; focused regressions improve **24/12 -> 24/0**, including seven shared
support examples. An independent parent rerun also passes all 24. Reviewed
deployer/file-reader consumers do not turn unreachable results into successes;
node deployment still requires its own functional qualification.

Joomla's original functional run had **12 cases/two failures**. Its impossible
range conjunction marked fixed 4.2.8 as Appears, while missing version metadata
was incorrectly Safe. The repair uses the actual affected range and returns
reason-bearing Unknown for unavailable/malformed versions. The final run passes
**12/0**; focused regressions improve **18/8 -> 18/0**, including seven shared
support examples. Check remains passive version evidence; it does not claim to
prove exploitability on a metadata-hardened target.

Credential development first caught two fixture errors before module execution:
the stock PostgreSQL loopback policy accepted an incorrect password, and the
SQL probe assumed a nonexistent login-proof column. Explicit host SCRAM policy
and queries against the real migrated schema corrected those assumptions.
Native accepted/rejected authentication then passed. An eight-case intermediate
suite passed before expanding to the final **11/0** cases; no production change
was needed for this profile.

## Integrated evidence and checks

- Ansible final: `tmp/module-target-tests/20261109T184217-94e597/ansible`,
  14 cases, 412.131802 seconds including bootstrap/native controls. Its original
  run is `20261109T183058-cf9449/ansible`.
- Joomla final: `tmp/module-target-tests/20261109T185954-0eb712/joomla_api`,
  12 cases, 73.202808 seconds including bootstrap/native controls. Its original
  run is `20261109T185257-263630/joomla_api`.
- Credentials final: `tmp/module-target-tests/20261109T191437-c4d594/credential_reporting`,
  11 cases, 86.141997 seconds including bootstrap/native controls.
- Aggregate selector: `tmp/module-target-checkpoint-ansible-joomla-reporting-current.json`.
  Its sole warning names the explicitly unqualified WordPress admin reproducer.

All 92 imported Ansible and 65 imported Joomla regular files were independently
verified byte-for-byte, with all 43 and 45 respective final input hashes current.
All 57 credential-profile input hashes are current. Worker paths, revision and
commands remain original; raw provenance was not rewritten. Durable exports
retain original failures, native/unit evidence and reports; the parent verified
all 267 Ansible and 197 Joomla export checksums. Ansible's final dependency set
adds the existing INI parser explicitly; its original run retains the smaller
declared set.

Resource audits find four Ansible and three Joomla projects empty, with their
four and ten recorded volumes absent. All four credential runner projects are
empty and all eight recorded anonymous volumes are absent; its separate native
authentication probe also completed owned teardown. No unrelated resources were
changed. Selected hashes describe declared inputs, not a complete dependency
graph. The remaining families retain their selected passing evidence; they were
not all rerun for these scoped changes.

New code passes focused lint/syntax and diff checks. Existing helper/module
diagnostics have no additions. Credential module-document comparison retains
the same 19 inherited diagnostics before/after. The existing MySQL prefix spec
also received a separate test-only correction: a deterministic reproduction of
CI's shared progress state failed before the change; all 16 focused examples now
pass with explicit nil/present progress cases and exact one-prefix assertions.
No production MySQL behavior changed.

## Limits and continuing investigations

Other Ansible releases/platforms, executable discovery, vault/dynamic inventories
and deployment remain separate work. Other Joomla releases, languages, large
pagination and persistence are unqualified. Credential coverage does not qualify
every reporting module/type, remote HTTP data services or upgrade persistence.
WordPress admin repeated staged sessions remain unqualified. Drupal and JBoss
have active native-controlled investigations and are excluded from these totals.
Eight source-hashed OS/kernel/device reviews remain individual requirements;
hundreds of container hints and other modules still await review.

At published revision `28d7dc6337f`, SSH, LDAP, Lint, MSSQL, PostgreSQL, SMB,
MySQL and command-shell CI passed in the refreshed snapshot; Meterpreter
acceptance remained queued.
[Verify failed](https://github.com/dwelch-r7/metasploit-framework/actions/runs/42675151247)
on an existing certificate/SID OpenSSL `first num too large` error and the
order-dependent MySQL prefix expectation. The latter is now reproduced and
corrected locally as described above. Certificate owning source/spec are
unchanged and causality remains unclassified. New pushes need separate CI
inspection; there is no overall green-CI claim.
