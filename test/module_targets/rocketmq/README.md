# RocketMQ module lab

Run one fresh project with the campaign's shared resource guard:

```sh
bundle exec ruby tools/dev/run_guarded_module_target_tests.rb rocketmq
```

This lab uses the genuine Apache RocketMQ 4.9.4 and 5.1.1 distributions, pinned
by image digest. Each target colocates its NameServer and Broker, matching the
module's use of the NameServer address when connecting to the Broker. Each
Broker advertises its actual container address and listens on port **10921**,
so enumeration must retain the real endpoint. Exploit-side automatic port
selection remains part of the separate execution qualification. Only NameServer ports
are published, on random host loopback ports. Framework shares the project
bridge for the Broker connection and reverse sessions.

The launcher selects ordinary bounded JVM heaps, thread pools and message-store
sizes. It starts the distribution's original server main classes, without
changing request handlers, protocol encoding or security checks. Each target is
limited to 640 MiB, 0.25 CPU and 256 PIDs, with no additional swap. Neither target
is privileged. The Framework console has its separate 768 MiB/one CPU limit.

`NativeProbe.java` compiles against **each target's bundled SDK jars**. It checks
the real topic route, advertised nondefault Broker endpoint, server version and
configuration. Before owning module calls, a same-value configuration update
checks the administration path. A fresh native SDK injection then requires a
fresh command-created marker on 4.9.4 and its absence on 5.1.1. Both configuration
values are restored, and the marker is removed. The fixed version's acceptance
of an update alone must not be treated as successful execution.

The functional cases exercise the scanner and exploit's version check twice per
release, real unsupported requests on the Broker port and refused connections.
Native snapshots after the cases must match the initial logical configuration,
route and Broker PID. Real transport results and console output are retained;
the observation mixin calls through to the production helper unchanged.

The scanner is the only module registered for qualification in this initial
profile. Full exploit command execution, payload delivery, sessions and session
cleanup remain unqualified until their own functional cases pass. A check alone
does not qualify the exploit. No module is qualified merely by adding these
files; consult the dated verification report for actual results.

This profile covers IPv4, the default JSON serialization, and ACL-disabled
targets. Other releases, IPv6, binary serialization and authenticated
administration remain outside its qualification. The Broker-port negative is a
real error reply containing a valid server version and no topic route; the
modules should retain that version without inventing Broker data or crashing.

The native injection can wait for the upstream FilterServerManager's 30-second
schedule. The vulnerable control returns as soon as the marker appears; the
fixed control observes a full 36-second window. The lab does not shorten the
server's timer or create the expected marker through a fixture shortcut.

Upstream references:

- [4.9.4 Broker startup and ordinary configuration loading](https://github.com/apache/rocketmq/blob/rocketmq-all-4.9.4/broker/src/main/java/org/apache/rocketmq/broker/BrokerStartup.java)
- [4.9.4 FilterServerManager execution schedule](https://github.com/apache/rocketmq/blob/rocketmq-all-4.9.4/broker/src/main/java/org/apache/rocketmq/broker/filtersrv/FilterServerManager.java)
- [4.9.4 shell execution](https://github.com/apache/rocketmq/blob/rocketmq-all-4.9.4/broker/src/main/java/org/apache/rocketmq/broker/filtersrv/FilterServerUtil.java)
- [5.1.1 administrative request handling](https://github.com/apache/rocketmq/blob/rocketmq-all-5.1.1/broker/src/main/java/org/apache/rocketmq/broker/processor/AdminBrokerProcessor.java)

The runner removes the project's containers, network and volumes after success
or failure. Preserve the run directory under `tmp/module-target-tests/` to
investigate failures. Classify native/setup failures before changing a module
or its expected output.
