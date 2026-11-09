# Native MQTT CONNECT responses

Captured on 2026-11-09 from actual Eclipse Mosquitto 2.0.22 on Alpine 3.23.8,
using digest-pinned image:

`eclipse-mosquitto:2.0.22@sha256:81a6193ae693942a3231cd3ac52875b02b7e3a19da671b2fb4b55cc874c5b279`

`capture_connect.rb` constructs a small MQTT 3.1 CONNECT using only Ruby's
standard socket library and the protocol wire format. It does not use Framework
or the mqtt gem. The accepted anonymous and refused password replies are actual
CONNACK packets. The unrelated Apache HTTP2.4.62 service returns no bytes before
the bounded two-second read deadline; its independent HTTP GET returns 200.

Run against a live owned target runner's runtime map:

```sh
ruby spec/file_fixtures/rex/proto/mqtt/capture_connect.rb tmp/module-target-tests/RUN/mqtt/runtime.json
```

The fixture omits ephemeral endpoints. Short/empty bodies, wrong MQTT packet
types and HTTP byte strings in focused specs are derived boundaries, not claims
of additional native captures. Native TCP fragmentation, MQTT3.1.1 client
requests and arbitrary broker implementations remain separate qualification work.
