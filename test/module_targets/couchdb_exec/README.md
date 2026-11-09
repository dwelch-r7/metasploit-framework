# CouchDB command execution targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb couchdb_exec
```

This profile reuses the original digest-pinned CouchDB 1.6.1 open/admin-party and
administrator-configured targets, plus original 3.3.1 for a fixed-version check.
The shared Framework container receives callbacks only on the owned project
network. Native controls verify release/authentication, independently trigger a
query-server command and read its actual target-side proof file before module
execution. A short bounded HTTP timeout is expected because the harmless touch
command does not speak the query-server protocol; a new filesystem side effect
is mandatory. Target software is genuine CouchDB, without API response stubs.

Apache describes the [configuration command execution issue](https://docs.couchdb.org/en/stable/cve/2017-12636.html)
and the separate [duplicate-role privilege escalation](https://docs.couchdb.org/en/stable/cve/2017-12635.html).
The tests exercise actual command-shell/Meterpreter sessions and read fresh
target-side command proof owned by the CouchDB service user. State-changing
deliveries repeat twice. A username colliding with a configured administrator
can create a shadow user but still fail authentication. That case must stop before staging, leave database/
query-server/file state unchanged, and permit explicit operator account removal.
A genuine existing-administrator user document causes HTTP 409; valid existing
access must still open sessions without claiming a newly completed bypass.
Effective roles are checked through the actual session;
parsing the duplicate-key user document is not an authorization test. The API
database, user and query-server changes are explicitly restored by the test;
that restoration must not be confused with the module's file cleanup.

A profile definition alone does not establish success. See the
[campaign](../CAMPAIGN.md) for actual results and failures. CouchDB 2.x, wget
delivery (absent from the stock 1.6.1 image), TLS, restricted service accounts,
other platforms and saved credentials remain unqualified. See the
[shared guide](../README.md) for evidence and owned-project cleanup.

Native REST controls disable Net::HTTP's automatic retries: a timed-out DELETE
can already have committed, so replaying its old revision produces a misleading
409. Ordinary native reads/writes have a ten-second bound; the intentionally
non-protocol native command trigger retains its separate three-second bound.
Cleanup re-reads the current user revision on conflict and verifies the final
native state. Module network settings and functional success assertions remain
independent of this fixture cleanup.
