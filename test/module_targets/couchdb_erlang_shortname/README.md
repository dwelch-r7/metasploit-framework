# CouchDB short DNS node-name qualification

Run from the repository root:

```sh
MODULE_TARGET_NAMESPACE=my-couchdb-lab bundle exec ruby tools/dev/run_guarded_module_target_tests.rb couchdb_erlang_shortname
```

This is the shorter-name counterpart of the
[DNS node-name lab](../couchdb_erlang_named/README.md). Only the supported hostname
and `NODENAME` change to `db.test`, producing the real node `couchdb@db.test`.
It uses the same genuine CouchDB3.2.1/OTP23 image, explicit historical cookie,
vendor RPC authentication/byte controls and two owning check/command cases.

Testing names shorter and longer than the original `127.0.0.1` setting avoids
treating a single replacement challenge length as general node-name support.
The two capped containers run serially and are immediately removed with their
owned ephemeral network and volume. Broader protocol/OS/release coverage remains
separate.
