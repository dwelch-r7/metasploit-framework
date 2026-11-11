# Memcached UDP scanner lab

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb memcached_udp
```

Four serial-owned containers are capped at 960 MiB and 1.3 CPUs. Official pinned
1.4.39 and 1.6.26 servers explicitly enable UDP; another 1.6.26 server disables
it while retaining a working TCP service. The default network is internal, and
published UDP ports use random loopback bindings. No host namespace is joined.

Before/after native clients run in Framework's namespace using only Ruby's
standard sockets. They verify actual TCP versions, UDP settings, complete
fragmented UDP version/stats responses, UDP-disabled and closed-port controls.
The module's sockets and protocol implementation remain unchanged.

Ten functional examples run both modules twice on each enabled release, disabled
UDP, a closed port and a multi-host batch. A passive AF_PACKET observer, using
the container's ordinary NET_RAW capability, records each actual module request
and reply. Exact complete fragments, versions, response payload sizes and printed
amplification calculations must agree. Sizes describe UDP application payloads,
including Memcached's eight-byte header, rather than Ethernet/IP overhead.

The existing NTP acceptance observer records reporting API calls and still calls
their production methods. Its historical filename is `ntp-reports.jsonl`.
Service/vulnerability arguments are checked per host and run; no SQL persistence
is claimed. The lab creates no cache entries, sessions or target files. Spoofed
source delivery, IPv6 and other releases remain separate scope. Configuration
alone is not passing evidence; actual results belong in the campaign report.
