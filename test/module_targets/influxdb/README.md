# Genuine InfluxDB enumeration target

This disposable lab uses official InfluxDB1.8.10 Linux amd64, pinned by platform
manifest digest, with its unchanged vendor entrypoint/initialization. Three
independent servers provide authenticated, authentication-disabled and empty
states. A real Apache reverse proxy supplies `/influx/`; unrelated Apache and a
closed target port provide negatives. Root/root and the reader credentials are
public artificial fixtures. Random published ports bind to127.0.0.1.

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb influxdb
```

Native CLI/version/process and real HTTP query/auth controls must pass before
Framework executes. Seeded database names include spaces; a restricted reader
can see only its granted database. Fixed-timestamp line protocol points include
Unicode. Native CLI and HTTP observations establish the expected database/user/
query rows, empty state, access refusals, proxy path and actual error semantics.
The functional tests compare parsed loot to those exact documents and preserve
state across repeats. The module is an enumeration utility; no session is expected.

The suite remains unqualified until a complete strict runner result has16 cases,
zero failures/pending/outside errors, current input hashes and successful owned
teardown. Native controls alone do not qualify the module. Do not reinterpret
silently ignored credentials on an authentication-disabled server as successful
credential validation. Missing required module options can fail validation before
any network operation; native anonymous refusal is recorded separately.

The ordinary project bridge has normal Docker egress; no outbound-filtering claim
is made. No privileged service, host socket, custom server response, project
library dependency or host database is used. Official image data volumes are
owned per-run and removed with the project; build images remain caches.

Qualified scope will be the recorded1.x InfluxQL REST interface and exercised
query/auth/path branches. This profile does not claim2.x/3.x compatibility, Flux,
TLS, clustering, arbitrary write/admin queries or every retention policy.

Primary API references:
[InfluxDB authentication](https://docs.influxdata.com/influxdb/v1/api/authentication/),
[InfluxQL query API](https://docs.influxdata.com/influxdb/v1/api/query/).
The vendor image revision and exact manifest metadata are retained with native
campaign evidence. Existing human console Scenarios are preserved.
