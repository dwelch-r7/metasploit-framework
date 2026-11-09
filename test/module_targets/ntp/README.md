# Native NTP control queries

This profile is under qualification. Run from the repository root:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb ntp
```

Ubuntu 22.04 supplies pinned upstream ntpd/ntpq 4.2.8p15. The real daemons
serve information with query access allowed or refused. They have no peers,
clock sources, host mounts or additional capabilities. Configuration disables
both time/frequency and kernel clock discipline; Compose explicitly drops
`SYS_TIME`. Native inspection checks the effective capability mask. Startup
clock-initialization requests can log `Operation not permitted`; granting clock
access is not required to serve these queries.

The [upstream option reference](https://www.ntp.org/documentation/4.2.8-series/miscopt/)
describes these discipline switches. Official `ntpq` queries independently
establish version, operating system, processor, a configured information
variable, and the remote query-policy boundary. A separate standard-library
wire probe records complete Mode 6 replies and actual datagram lengths.

All probes are single ordinary requests directed only to owned targets.
`SRCIP` is omitted so Framework uses ordinary UDP sockets. No spoofed packets,
traffic flood or external NTP server is involved. Published ports bind only to
random loopback addresses. A real BIND daemon is the unrelated UDP control.

The acceptance observer records the arguments passed to `report_service` and
`report_vuln` while preserving their original calls. This exposes gathered
information without requiring a database; it does not qualify database storage.
Assertions compare real native properties and wire lengths, including repeated
runs and denied/unrelated controls. Mode 7 monlist, IPv6, authentication, time
synchronization and other ntpd releases remain unqualified.
