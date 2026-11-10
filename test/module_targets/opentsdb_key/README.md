# Genuine OpenTSDB key profile

Run `bundle exec ruby tools/dev/run_module_target_tests.rb opentsdb_key`.

See [shared target setup and limits](../opentsdb/README.md). This profile uses
OpenTSDB 2.4.1, an isolated genuine HBase, real graph generation, an authenticated
Apache prefix and an unrelated Apache service.
