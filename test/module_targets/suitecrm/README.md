# Native SuiteCRM export credential collection

This lab uses the official SuiteCRM **7.12.5** release ZIP and a **7.12.6** fixed
control with PHP **7.4.33**, Apache and MariaDB **10.6.19** on Linux amd64.
Archives and base images are SHA-256 pinned; the release ZIPs include their
vendor dependencies. Historical, normally signed Debian snapshot indexes pin
the PHP extension build environment. PHP OPcache keeps blind extraction short.

Run from the Framework root with Docker Compose and the repository Ruby bundle:

```sh
MODULE_TARGET_NAMESPACE=local-suitecrm bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb suitecrm suitecrm_fixed suitecrm_names
```

The guarded runner serializes the profiles, builds and installs the real product,
checks native prerequisites, runs the owner through msfconsole, records evidence
under `tmp/module-target-tests/`, and removes only the created project and volumes.
Each profile has three services: app 768 MiB/1 CPU, MariaDB 384 MiB/0.5 CPU and
Framework's reporting PostgreSQL 384 MiB/0.25 CPU, with 128 PIDs each. Ports bind
to localhost. MariaDB uses the private internal network. No host files or Docker
socket are mounted. Completed stacks are removed immediately; campaign cleanup
also removes unused task-created containers up over an hour and preserves other
namespaces. An interrupted or failed teardown must be resolved before another
profile starts.

## Genuine setup and independent controls

The official silent installer creates the administrator. Native BeanFactory and
User APIs create one Account and a second user; no login, export, SQL handler or
module method is replaced. Automatic product update checks and anonymous stats
are disabled. The disposable login is `labadmin` / `Module-suite-admin42!`.
The nonadministrator fixture is `viewer` / `Module-suite-viewer42!`.
These values belong only to this local lab.

Independent HTTP controls authenticate, load About, export the real Account and
repeat true/false injection requests. On 7.12.5 the true request includes the
Account while the false request produces only the CSV header; on 7.12.6 both
injected requests produce only the header while ordinary export still works.
Wrong-password controls must return the genuine login form and redirect route.
Native database snapshots and the original release's export-handler hash are
checked before and after Framework execution.

## Automated coverage

The baseline and fixed profiles each have eight cases. The vulnerable profile verifies passive `Appears`,
`COUNT=1` twice with both AutoCheck modes on the same configured console module,
`COUNT=0`, the actual default count, wrong credentials with AutoCheck on/off,
negative COUNT and an unavailable endpoint. Framework may replicate the selected
console module for each execution. Passive tracing records the actual owner
entries and selected usernames without replacing behavior.

Collected bcrypt bytes must exactly match native users, with exact credential
cardinality, hash type, JtR format, origin module and service endpoint. Repeats
must not add duplicate credentials. The fixed profile verifies reason-bearing
`Safe` and AutoCheck refusal without collection, plus authentication/connection
errors. Selected user/Account state, resource events, empty session/job sets and
owned Docker teardown are checked. The latest replay is **22/0**, plus **70/0** focused regressions; see the
[current verification record](../VERIFICATION-20261118-suitecrm-names.md).
The [names profile](../suitecrm_names/README.md) adds six cases for native UTF-8,
commas/apostrophes, administrator and nonadministrator collection, repeated
configuration and long/byte inference controls. Usernames are selected as
individual HEX rows, avoiding delimiter and server aggregation limits.

Only the root application path, these two releases and this MariaDB/PHP
combination are qualified. The names profile adds the seeded UTF-8 username
with a comma and apostrophe, using both administrator and local nonadministrator
collectors. Other names, versions, URL prefixes, TLS, database engines and
additional authentication/authorization configurations need separate evidence. The existing CVE mapping
is an explicitly unresolved metadata investigation in the verification record.
Existing human-written module Scenarios are unchanged.
