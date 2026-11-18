# Native SuiteCRM usernames and collector roles

This profile uses official SuiteCRM 7.12.5 and the same pinned PHP/MariaDB target
as [the shared guide](../suitecrm/README.md). The stock native User API renames
the seeded nonadministrator to `aé,o'neil`, following SuiteCRM's HTML-encoded
bean input contract. Native persistence decodes it; raw database HEX output and
ordinary login/export prove the stored bytes and real account access. The shared
[names fixture](../suitecrm/names.json) owns the username and disposable password.
No application response, export handler or Framework module method is replaced.

```sh
MODULE_TARGET_NAMESPACE=local-suitecrm bundle exec ruby \
  tools/dev/run_guarded_module_target_tests.rb suitecrm_names
```

Six cases verify checks for both identities, actual 1600-byte length and UTF-8
column inference, administrator COUNT=1 to COUNT=0, nonadministrator repeats with
both AutoCheck modes, and bad-password refusals with AutoCheck on/off. Exact
selected usernames, native bcrypt values, credential cardinality/type/origin/
endpoint, configured-module reuse and selected native state are checked. The
names profile passes **6/0**; all three profiles pass **22/0** with **70/0** focused
regressions. See the [verification record](../VERIFICATION-20261118-suitecrm-names.md).

Three capped services run: app 768 MiB/1 CPU, MariaDB 384 MiB/0.5 CPU and reporting
PostgreSQL 384 MiB/0.25 CPU, 128 PIDs each. Completed owned projects/volumes are removed
immediately; unrelated containers are preserved. An earlier direct-oracle
candidate was rejected by real SuiteCRM HTML escaping; the final wire predicates
and genuine-CSV guard are tested against the unchanged product. Other names,
versions, deployment prefixes, TLS and additional authorization settings remain
outside this profile's native evidence. Human Scenarios are unchanged.
