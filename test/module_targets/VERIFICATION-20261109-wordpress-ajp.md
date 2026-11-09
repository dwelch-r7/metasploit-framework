# WordPress and Tomcat AJP qualification

The current selected checkpoint covers **98 production runtime modules, 38
families and 550 functional cases**. Every selected result has its exact expected
count, zero failures/pending/outside-example errors, matching current recorded
input hashes and successful owned teardown. The preceding 94-module, 36-family,
498-case checkpoint remains current; WordPress adds three modules/39 cases and
Tomcat AJP adds one module/13 cases. The broader repository campaign is active.
No pull request was created, and the full local repository RSpec suite was not run.

## Reusable targets and independent controls

Target source, Compose definitions, manifests and guides remain together under
`test/module_targets/<family>/`, linked from the existing module documentation.
Functional cases use real console entry points under
`spec/acceptance/module_targets/`. Native controls precede module assertions;
container health and module completion alone never establish success.

| Family | Real target and independent controls | Functional cases |
|---|---|---:|
| [WordPress](wordpress/README.md) | Official digest-pinned 6.8.3/PHP 8.3.28 Apache with MariaDB 11.2.2; native PHP installation/account/component APIs and 80 actual HTTP requests | 39 |
| [Tomcat AJP](tomcat_ghostcat/README.md) | Official digest-pinned Tomcat 8.5.50/8.5.51 with OpenJDK 8; native file reads and an independent standard-library AJP client, 21 actual requests | 13 |

WordPress covers root/subdirectory installations, pretty/plain permalinks,
published authors, accessible/protected bundled metadata, version-only and empty
shortlists, exact username loot, username validation, repeated HTML/XML-RPC
authentication, special/wrong/blank passwords, role permission refusals and
blocked/unrelated endpoints. Four genuine installations have separate databases.
The readable Akismet readme configuration is explicit; the protected profile
retains its vendor access rules. Native authenticated profile identity and
XML-RPC permission faults distinguish valid credentials from rejected ones.

Tomcat controls establish ordinary AJP success on both releases, HTTP protection
of `WEB-INF`, exact affected-server private-file bytes and patched-server
attribute refusal. The patched profile disables the newly required AJP secret
while retaining request-attribute restrictions, isolating that boundary from an
unreachable connector. Files include the default web.xml resource, short,
54,272-byte, empty, Unicode and binary data. Complete raw frames and native file
bytes are retained independently of the module's parser.

Only random loopback target ports are published. Framework source is mounted
read-only, target state is disposable, and no host Docker socket or listener is
exposed. Cold console starts were serialized through an observed first prompt
and metadata snapshot. Runtime evidence retains image identities, native
commands, console output, loot, exact counts, hashes and teardown records.
An independent cleanup audit found no containers, networks or project volumes
across the 12 new owned projects; all 35 recorded anonymous volumes were absent.
The receipt is `tmp/wordpress-ajp-owned-resources-audit.json`.

## Verified failures and repairs

The initial WordPress parent run produced **39 cases/11 failures**, with native
preflight passing. Ten XML-RPC cases rejected a genuine HTTP 405 POST-only
endpoint. One scanner case missed WordPress's native query-based REST route
when plain permalinks made `/wp-json/` return 404. HTML authentication,
username validation and username loot already passed.

- `wordpress_scanner`: a module-local query-route fallback follows HTTP 404;
  explicit permission refusals are retained. User-list and entry shapes are
  validated before reporting. The shared URI helper remains unchanged.
  Matched isolated functional results: **8/1 -> 8/0** failures. Focused captured
  response regressions: **27/9 -> 27/0**, including seven shared support cases.
- `WordpressRPC`: recognizes the actual 405 endpoint and serializes exact
  credentials as escaped UTF-8 XML. Sending the original library-generated
  special password to the genuine endpoint produced parse fault -32700; the
  repaired request produced the expected permission-only 401 fault. Structured
  parsing handles absent replies and rejects malformed/non-200 evidence;
  successful user-list evidence needs a typed positive numeric identifier.
  Malformed-ID boundaries are derived robustness cases, not additional live
  faults. Matched functional results: **12/10 -> 12/0**. Focused new and existing
  contract cases: **86/14 -> 86/0**, including seven shared support cases.
- `tomcat_ghostcat`: appends every body chunk, represents valid empty files as
  empty byte strings, refuses incomplete/malformed replies, and prints/stores
  file contents only after a successful read. The original implementation lost
  earlier large-file chunks and saved actual 403/500 error pages as successful
  file loot. The original 13-case run had four failures; one was an overly
  narrow harness assertion despite correct unrelated-protocol refusal. After
  correcting only that assertion, unchanged production source reproduced
  **13/3**, followed by **13/0** with the fix. Captured-frame regressions:
  **29/14 -> 29/0**, including seven shared support cases.

Each isolated functional comparison changes only its owning production source
among the recorded input bytes. Native readiness and teardown pass on both
sides. The parent integrated WordPress run passes all **39 cases** and its
combined relevant unit run passes **106 examples**. The complete Tomcat worker
13-case result was independently inspected and imported byte-for-byte; its
selected input hashes match the integrated parent tree. This avoids repeating
an identical passing suite. Imported evidence retains its original worktree,
revision, commands and project identity rather than being relabeled a parent run.

## Evidence and limits

- WordPress parent before: `tmp/module-target-tests/20261109T160148-15bea4/wordpress`.
- WordPress parent final: `tmp/module-target-tests/20261109T162227-2c12e8/wordpress`
  (39 cases, 113.125006 seconds including cold bootstrap/native controls).
- Tomcat initial assertion diagnosis:
  `tmp/module-target-tests/20261109T161549-41904a/tomcat_ghostcat`.
- Tomcat corrected unchanged-source baseline:
  `tmp/module-target-tests/20261109T161951-077987/tomcat_ghostcat`.
- Tomcat final imported worker result:
  `tmp/module-target-tests/20261109T162615-6f95f9/tomcat_ghostcat`
  (13 cases, 118.961381 seconds including cold bootstrap/native controls).
- The aggregate selector output is
  `tmp/module-target-checkpoint-wordpress-ajp.json`; its stderr is empty.
  These local raw artifacts are not committed into the repository.

New Ruby tests/probes have no lint offenses. WordPress production source retains
six inherited offenses across the two owning files; Tomcat retains its existing
AutoCheck information diagnostic. Syntax, msftidy and diff checks pass. Existing
WordPress documentation diagnostics are unchanged; Tomcat documentation has
none. Existing human Scenarios were preserved. WordPress's native JSON snapshots
emit UTF-8/BINARY warnings under JSON 2 while returning valid parsed evidence and
exit status zero; JSON 3 compatibility is not qualified by this run.

Qualification covers the pinned profiles and asserted paths. Other application
versions, localization, multisite, TLS, reverse proxies and Framework database
credential persistence remain unqualified. Tomcat covers resources in the web
application, not arbitrary filesystem reads, JSP execution or sessions. Its
existing 30-second socket read remains unchanged; delayed-frame timing is not a
newly qualified transport capability. Incomplete returned responses now fail
conservatively instead of becoming partial loot.

At the latest preceding published revision inspected (`bf53ffccd84`), LDAP CI
passed and nine workflows remained queued. There is no overall green-CI claim.
The prior [verification record](VERIFICATION-20261109-jenkins-udp.md) retains the
earlier Ruby 3.4 certificate/ASN.1 Verify failure and its unclassified causality.
Check the newly pushed revision separately rather than attributing those results
to it. No full local Framework suite was run.

WordPress administrator upload/session paths and Multicall remain valuable next
candidates for the shared lab. Multicall's separate 200-only library guard is a
source observation, not a verified failure of its production module. Most
repository modules still await individual feasibility review and qualification;
the six source-hashed OS/kernel/device reviews remain specific target
requirements rather than blanket exclusions.

## Current selected matrix

| Family | Cases | RSpec seconds | Selected local evidence |
|---|---:|---:|---|
| apache_normalize_path | 16 | 41.769 | `20261109T143602-89d864/apache_normalize_path` |
| axis2 | 12 | 186.317 | `20261109T143602-89d864/axis2` |
| couchdb | 8 | 38.248 | `20261109T143602-89d864/couchdb` |
| couchdb_exec | 9 | 243.001 | `20261109T143602-89d864/couchdb_exec` |
| couchdb_legacy | 9 | 14.375 | `20261109T143602-89d864/couchdb_legacy` |
| dns | 28 | 146.196 | `20261109T143602-89d864/dns` |
| elasticsearch | 11 | 53.445 | `20261109T152330-517255/elasticsearch` |
| ftp | 13 | 73.646 | `20261109T143602-89d864/ftp` |
| http | 14 | 56.801 | `20261109T142833-bf0fc5/http` |
| jenkins | 51 | 353.931 | `20261109T143705-1f597e/jenkins` |
| jenkins_command | 8 | 93.274 | `20261109T151223-9835bb/jenkins_command` |
| ldap | 10 | 18.506 | `20261109T143602-89d864/ldap` |
| linux_post | 8 | 183.303 | `20261109T143602-89d864/linux_post` |
| linux_system | 12 | 421.908 | `20261109T143602-89d864/linux_system` |
| mail | 13 | 107.133 | `20261109T143602-89d864/mail` |
| mariadb | 10 | 16.913 | `20261109T143602-89d864/mariadb` |
| memcached | 4 | 41.084 | `20261109T143602-89d864/memcached` |
| mongobleed | 11 | 45.717 | `20261109T143602-89d864/mongobleed` |
| mongodb | 31 | 70.715 | `20261109T143602-89d864/mongodb` |
| mongodb_legacy | 12 | 16.475 | `20261109T143602-89d864/mongodb_legacy` |
| mqtt | 10 | 39.546 | `20261109T143602-89d864/mqtt` |
| mssql2019 | 15 | 68.330 | `20261109T143602-89d864/mssql2019` |
| mssql2022 | 15 | 32.317 | `20261109T143602-89d864/mssql2022` |
| mysql8 | 10 | 19.399 | `20261109T143602-89d864/mysql8` |
| ntp | 6 | 36.885 | `20261109T150045-2bb9a0/ntp` |
| postgres | 9 | 17.209 | `20261109T143602-89d864/postgres` |
| redis | 22 | 117.224 | `20261109T143602-89d864/redis` |
| rsync | 6 | 21.850 | `20261109T143602-89d864/rsync` |
| smb | 20 | 56.139 | `20261109T143602-89d864/smb` |
| smtp | 9 | 33.087 | `20261109T143602-89d864/smtp` |
| snmp | 22 | 57.040 | `20261109T143602-89d864/snmp` |
| ssh | 2 | 18.442 | `20261109T143602-89d864/ssh` |
| tftp | 6 | 62.214 | `20261109T141732-e65fed/tftp` |
| tomcat | 14 | 133.636 | `20261109T143602-89d864/tomcat` |
| tomcat_ghostcat | 13 | 118.961 | `20261109T162615-6f95f9/tomcat_ghostcat` |
| vnc | 20 | 88.595 | `20261109T143602-89d864/vnc` |
| webdav | 22 | 152.646 | `20261109T143602-89d864/webdav` |
| wordpress | 39 | 113.125 | `20261109T162227-2c12e8/wordpress` |
