# CouchDB Erlang owner qualification

Run from the repository root:

```sh
MODULE_TARGET_NAMESPACE=my-couchdb-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb couchdb_erlang
```

The digest-pinned official CouchDB 3.2.1 image contains genuine OTP23. Its
entrypoint omits the source package's old cookie default, so this fixture
explicitly sets `COUCHDB_ERLANG_COOKIE=monster` to reproduce the affected
historical configuration. It does not modify CouchDB code. HTTP administrator
credentials are public lab data; Erlang owner execution uses no HTTP login.

Before owning calls, vendor Erlang with the bundled `start_clean` boot file
proves actual service/runtime identity, correct/wrong cookies and exact repeated
UID-5984 command writes. An independent native EPMD request records the real
advertised distribution port. The initial owning cases exercise check and a
benign command; setup, fixture and module failures must remain distinct.

The target and Framework console are capped, namespaced and immediately removed
with their anonymous volumes on completion or interruption. No reporting database
is used. Broader targets, sessions, delivery families and fixed-release controls
remain under investigation; this draft is not a blanket module qualification.
