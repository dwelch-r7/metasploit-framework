# Legacy CouchDB targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb couchdb_legacy
```

The original digest-pinned CouchDB 1.6.1 image runs with native open/admin-party
and configured-administrator profiles. Only random loopback ports are published.
Native controls validate the actual release, users, anonymous database listing,
real nested documents, text/binary attachment bytes and incorrect credentials.

On the administrator-configured target, an independent native request uses the
duplicate-role-key vulnerability to create a temporary administrator without
credentials. It checks actual identity/roles, deletes that account and confirms
its removal. The open target alone would not establish authorization bypass.

Functional cases cover vulnerable-version checks, both access profiles, exact
database/document loot, valid/incorrect credentials and repeated CREATEUSER
operations. The operator-requested account creation is expected to persist;
the test explicitly deletes its temporary accounts through the native API.
This verifies repeated controlled operations, not automatic module deletion.

See the [campaign](../CAMPAIGN.md) for actual results; a definition alone is not
a passing result. Other releases, CVE command execution, TLS, proxies and saved
credentials remain unqualified. See the [shared guide](../README.md) for evidence
and owned-project cleanup.
