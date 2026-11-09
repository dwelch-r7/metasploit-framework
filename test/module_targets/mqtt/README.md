# Native MQTT authentication targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb mqtt
```

The digest-pinned Eclipse Mosquitto 2.0.22 image on Alpine 3.23.8 supplies the real
broker and publisher/subscriber clients. Four services provide anonymous,
password, client-ID-prefix and authenticated TLS policies. A fifth service is
real Apache HTTP. Lab credentials are `lab-mqtt-user` / `lab-mqtt-password`; the
prefix-restricted service accepts only client IDs beginning with `module-target-`.
No host broker or external topic is used. Each published port binds to a random
loopback port, following the [shared guide](../README.md).

The TLS identity is generated from included Ruby source solely for the owned
lab. Native clients validate its certificate through the explicit lab CA file.
Framework cases use explicit SSLVerifyMode NONE to test encrypted password
authentication with that public self-signed identity; Framework certificate
validation is outside this profile.

Independent native clients verify accepted/refused CONNACK packets, valid and
incorrect credentials, missing authentication, enforced client-ID prefixes and
TLS. Retained-message publish, exact readback, removal and verified absence run
twice per policy. This proves real broker behavior independently from Framework's
MQTT packet parser and credential scanner.

Native controls also accept MQTT3.1 on every policy. Framework's current packet
gem defaults to that protocol, whose client IDs are limited to 23 bytes; the
explicit prefix case therefore uses a short ID. MQTT3.1.1 native message controls
do not establish that Framework sends that protocol version.

Ten module cases cover anonymous detection, repeated valid password connections,
incorrect/unknown/blank credentials, ordinary/refused and explicit/accepted client
IDs, TLS authentication and an unrelated-service negative. Each credential case
uses one candidate with dictionary/database sources disabled. Native message
round trips validate the fixture; the module's function is CONNECT authentication.

This family is under module qualification. Consult the [campaign](../CAMPAIGN.md)
for actual results and defects. MQTTv5 authentication, mutual TLS/PSK, topic ACLs,
persistent sessions, WebSockets, other brokers and credential database persistence
remain unqualified.
