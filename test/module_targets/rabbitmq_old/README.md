# RabbitMQ 3.8.16 serial AMQP profile

Run this profile with the other release serially:

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default MODULE_TARGET_NAMESPACE=mcv-example \
  bundle exec ruby tools/dev/run_guarded_module_target_tests.rb rabbitmq_old rabbitmq_new
```

The shared [RabbitMQ fixture](../rabbitmq/README.md) supplies genuine pinned
broker, Pika and PostgreSQL images. This profile selects only `old`; its nine
cases cover TCP/TLS discovery, credential reporting and repeatability, incorrect
password recovery, limited-vhost credentials, remote guest refusal, workspace
isolation and native preservation. AMQP controls run before owning modules.
Erlang distribution/RPC controls are left to the separate Erlang profile.

Each phase has four containers: broker (768 MiB, one CPU), native client
(128 MiB, 0.25 CPU), reporting database (256 MiB, 0.5 CPU) and Framework
(1536 MiB, one CPU). PID and swap limits are explicit. The guarded runner
removes each complete project, including volumes, before the next phase.
The native client is removed immediately after its controls; only three
containers remain during owning module calls. Final native assertions run after
all examples, regardless of their randomized order.
