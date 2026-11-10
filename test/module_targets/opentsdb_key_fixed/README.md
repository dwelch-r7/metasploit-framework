# Genuine OpenTSDB key_fixed profile

Run `bundle exec ruby tools/dev/run_module_target_tests.rb opentsdb_key_fixed`.

See [shared target setup and limits](../opentsdb/README.md). This profile uses
OpenTSDB 2.5.0-RC1 at the exact fixed source revision, an isolated genuine HBase, real graph generation, an authenticated
Apache prefix and an unrelated Apache service.
