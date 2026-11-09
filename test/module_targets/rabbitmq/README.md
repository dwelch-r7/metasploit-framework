# RabbitMQ discovery and credential reporting

Run `bundle exec ruby tools/dev/run_module_target_tests.rb rabbitmq` from the
repository root. This disposable lab uses the canonical Framework console and
its own PostgreSQL database. All published target ports bind randomly on
127.0.0.1; no external broker or credentials are used.

The two genuine official Linux amd64 images are pinned by platform digest in
`compose.yaml`: RabbitMQ 3.8.16 (OTP 24 / ERTS 12.0.2) and RabbitMQ 3.12.14
(OTP 25.3.2.15 / ERTS 13.2.2.11). Native CLI queries and Pika independently verify
the actual runtime and AMQP identities. Python 3.12.12 and Pika 1.3.2 are pinned;
Pika's wheel is checked against the publisher SHA256 at build time.

Each broker has real AMQP TCP and TLS 1.2 listeners. A generated lab certificate
is explicitly trusted by Pika, including hostname verification. TLS client
certificates are not required. The public fixture configuration grants
`lab-amqp-user` / `module-target-amqp-password` access to `/`, while
`lab-amqp-limited` / `module-target-limited-password` can access only
`module-target`. `guest` / `guest` is explicitly restricted to loopback. The
newer official image normally overrides that guest policy; this lab removes
that image default and sets the policy explicitly rather than assuming it.

Health checks run the real vendor CLI as `rabbitmq` through the image
`gosu` helper. Running that CLI as root during first boot can create a
root-owned cookie after the vendor ownership scan and prevent broker startup.
Application and listener readiness are both required.

Before modules run, a separate Pika client checks accepted and rejected
credentials, guest restrictions, root-vhost refusal, and allowed-vhost message
publish/get round trips over both transports. It retains actual connection.start
bytes, server properties, mechanisms and TLS negotiation. Vendor CLI checks
users, permissions and the absence of leaked queues. Vendor Erlang RPC and
independent distribution handshakes are additional controls shared with the
Erlang lab.

The 17 examples verify both discovery outputs and database service records,
successful logins twice without duplicate credentials, wrong-password/guest
refusals, limited credentials, and workspace isolation. Independent SQL checks
the exact credential, origin, host, service, status and workspace associations.
The database itself requires TCP SCRAM and rejects a wrong password.

The login module confirms authentication when the broker sends connection.tune;
it does not open a virtual host. A valid limited account is therefore a valid
credential result even when independent Pika cannot open `/`. These cases do not
claim queue or vhost authorization from that scanner result.

This profile does not qualify AMQP 1.0, non-RabbitMQ brokers, alternate SASL
mechanisms, certificate authentication, TLS versions other than 1.2, clusters,
IPv6 or other RabbitMQ/OTP versions. The separate
[Erlang execution profile](../erlang_cookie/README.md) covers cookie command and
session behavior. Runtime results and hashes belong to the runner's evidence
directory; no generated transcript is added to human module Scenarios.
