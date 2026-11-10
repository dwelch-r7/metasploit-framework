# MySQL capture native-client profile

Run `bundle exec ruby tools/dev/run_module_target_tests.rb capture_mysql`.
The seventeen cases use genuine pinned Oracle and MariaDB clients, real native
server authentication, actual PCAP and independent challenge-response checks.
See the [database capture guide](../database_capture/README.md) for setup,
reporting, repeated execution, cleanup and qualification limits.
