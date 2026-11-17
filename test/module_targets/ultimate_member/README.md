# Ultimate Member genuine targets

These opt-in targets install unmodified official 2.8.2 and 2.8.3 plugin ZIPs
on pinned WordPress 6.8.3 / PHP 8.3.28 and MariaDB 11.2.2. The release catalog
pins complete archives and every installed archive file. The human module guide
and its Scenarios remain unchanged.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby test/module_targets/ultimate_member/prepare.rb
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ultimate_member
```

Run serially. Each stack has three capped containers: app 1 CPU / 512 MiB,
MariaDB 0.5 CPU / 512 MiB, PostgreSQL 0.25 CPU / 384 MiB. Equal memory/swap,
PID 128, init and loopback publication apply. PostgreSQL provides a fresh,
ordinary-role Framework reporting schema. Teardown removes attached objects.

Normal vendor activation creates the forms, directory and four native accounts'
member status. The native setup API creates its actual pages. The fixture selects
all WordPress roles through the normal post-metadata API. A fresh default empty
role selector returns no members before the custom-table data SELECT; retain that
state as a separate negative prerequisite, not a successful SQLi target.
The vendor's real nonce-checked admin operations enable and populate its custom
metadata table in separate PHP processes. The copied data must match actual core
metadata exactly. Vendor source is unchanged. Mail/remote integrations are disabled
by lab configuration and remain unqualified.

Native gates verify all four ordinary members, public page nonces, real directory
IDs, invalid nonce/directory rejection and independent true/false data-dependent
and module-shaped timing probes before and after public execution. Positive public
runs use actual installer page/directory IDs, COUNT=1 and SqliDelay=0.6. Complete
native password hashes, genuine credential/service/vulnerability reports, exact
loot contents, repeat IDs and unchanged source/users/configuration are required.
No HTTP, SQL, target protocol or reporting methods are replaced. The module has
no public check implementation; these profiles exercise its public run.

Profiles are setup registration until real runtime evidence is accepted. Record
actual results and limitations in the campaign journal; do not invent Scenarios.
