# FTP bounce scanner lab

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ftp_bounce
```

Four containers cap the serial lab at 960 MiB and 1.3 CPUs. Two normal ProFTPD
servers reuse the unchanged [FTP fixture](../ftp/README.md), with the supported
`AllowForeignAddress` setting enabled or disabled. An official pinned Apache
destination listens on ports 80, 8080 and 8082; port 8081 remains closed. Relays
are configured in both server and anonymous contexts. No FTP handler is replaced.

Before/after native ftplib controls verify local and anonymous authentication,
exact file retrieval, actual foreign PORT/LIST transfers, protected and closed
ports, low-port policy and rejected passwords. Actual destination HTTP access
records prove that directory-listing data arrived from the relay at each high
port. The module's claimed open ports and reporting API arguments must agree
with newly received data, including mixed lists/ranges and repeats.

The shared NTP observer records API calls while preserving production methods;
its historical filename is `ntp-reports.jsonl`. SQL persistence is not claimed.
The shared Ubuntu fixture resolves its distribution package during build;
verification records must retain the actual package/version/binary and image ID.
IPv6 is explicitly unsupported by this module. Other FTP products, invalid
option contracts and jitter timing remain separate. Configuration alone is not
evidence that the native gate or owning module passes.
