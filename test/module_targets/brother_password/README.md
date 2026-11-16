# Brother supplied-serial generation mode

This opt-in profile exercises the existing public module with `TargetSerial`
provided and `ValidatePassword=false`. It uses one ordinary-role PostgreSQL 16
container and a real isolated Framework console. There is no printer emulator.
The entire human module guide and Scenarios remain unchanged.

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default bundle exec ruby tools/dev/run_guarded_module_target_tests.rb brother_password
```

Nineteen public calls cover synthetic short/exact/long serials, the documented
sixteen-character truncation, lookup boundaries, explicit ASCII/eight-byte UTF-8
salts, repeated reporting, HTTP/HTTPS service-origin metadata, all explicit
serial-discovery selectors bypassed by a provided serial, and invalid settings.
The expected vectors come from the pinned original research PoC. The PoC and
module share algorithm ancestry, so agreement proves reference consistency;
it does not independently prove a real device's factory password.

[Reference source](https://github.com/sfewer-r7/BrotherVulnerabilities/blob/2909a4d3dbbf615321536811bfbbc4a9982b9fb4/CVE-2024-51978.rb)
is pinned at commit `2909a4d3dbbf615321536811bfbbc4a9982b9fb4`, whole-file SHA256
`8fa9f9fa8ed7309ea14b6c5407094e17b1ebc260dc1a6a4e47fd67f68bd98f5f`.
The captured vectors use only synthetic serials. Qualification generated them
with the reference class's pure derivation method; its CLI, constructor,
discovery and login methods were not run. The class-span digest is retained in
`reference-vectors.json`. Reference generation needs only Ruby's standard
library; the normal profile reads the saved vectors without fetching code.

Valid cases require the complete derived value, an actual password credential
and service origin, correct module context and **Untried** login status. Repeated
identical input must deduplicate. Invalid configuration must report its reason
and persist nothing. Separate loopback TCP/UDP sentinels provide no protocol
response and must receive no connection/datagram. No HTTP/SNMP/PJL transport,
credential reporting or login-result method is stubbed.

The profile checks a fresh schema and non-superuser reporting role before normal
Framework migrations. Its single reporting container is capped at 0.25 CPU /
384 MiB, with equal swap limit, PID limit 128, init enabled and a loopback port.
It reuses the existing Elasticsearch PostgreSQL definition without starting
Elasticsearch. All stack objects are removed after the run.

Actual discovery, successful/failed device login, printer models/firmware and
other salts remain unqualified and need a genuine device or runnable matching
firmware. This profile must not be described as a printer-authentication test.
Qualification results and exact input hashes belong in the campaign journal.
