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
