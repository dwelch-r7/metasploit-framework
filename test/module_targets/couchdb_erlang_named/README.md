# CouchDB DNS node-name qualification

Run from the repository root:

```sh
MODULE_TARGET_NAMESPACE=my-couchdb-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb couchdb_erlang_named
```

This profile changes only the supported `NODENAME` setting and matching container
hostname of the [CouchDB Erlang lab](../couchdb_erlang/README.md). The pinned
CouchDB3.2.1/OTP23 binaries and explicit historical cookie remain unchanged.
The real node is `couchdb@couchdb.example.test`; Docker supplies its local DNS and
hosts entry. Native vendor RPC must prove the actual node/runtime, reject an
incorrect cookie, and write exact quoted Unicode/CRLF bytes twice as UID5984
before the module's check and repeated command cases run.

This configuration exercises the variable node-name length in the distribution
challenge. A native prerequisite pass is necessary before classifying any owner
failure. The capped target/Framework pair is namespaced and immediately removed,
including anonymous volumes. Sessions, fixed releases and complete TCP framing
robustness are separate qualifications.

Sources: [CouchDB image settings](https://github.com/apache/couchdb-docker/blob/main/README.md),
[OTP23 distribution protocol](https://github.com/erlang/otp/blob/OTP-23.3/erts/doc/src/erl_dist_protocol.xml).
