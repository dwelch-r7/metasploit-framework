# CouchDB initial default and target reselection

Run from the repository root:

```sh
MODULE_TARGET_NAMESPACE=my-couchdb-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb couchdb_erlang_default
```

This profile reuses the genuine pinned CouchDB3.2.1/OTP23 target, native vendor
RPC controls and capped target/Framework pair from the
[session lab](../couchdb_erlang_sessions/README.md). A stock OpenSSL handler and
vendor RPC first establish a real session with UID/PID/file/shutdown proof.

The first owner use then reads its initial target and payload before any
`set TARGET` or `set PAYLOAD`. Neither option is passed to execution. Two owning
sessions must use the declared OpenSSL default and satisfy the same physical
proofs. This tests the initial module default rather than payload selection
after an explicit target command.

A separate case reads the selection before and after `set TARGET 0`. Current
console code invokes automatic payload selection even when the index remains0;
the observed PHP selection requires PHP, which is absent in this target. This
case verifies the configuration transition and does not run that PHP payload.
The earlier session fixture's PHP observation occurred after this command.

The two cases retain source binding, input/output, actual callback metadata,
service health, empty Framework jobs/sessions and immediate owned cleanup.
The inherited wget package supports shared native controls; the OpenSSL owner
path itself uses no PHP or wget. Complete ancestry/socket/database closure,
Windows, other cookies/releases/node names and PHP execution remain separate.
