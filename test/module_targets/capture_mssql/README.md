# MSSQL capture native-client profile

Run `bundle exec ruby tools/dev/run_module_target_tests.rb capture_mssql`.
The twelve cases use genuine FreeTDS clients, SQL Server 2019 native controls,
actual LOGIN7/NTLM bytes and independent cryptographic verification.
See the [database capture guide](../database_capture/README.md) for setup,
reporting, repeated execution, cleanup and qualification limits.
