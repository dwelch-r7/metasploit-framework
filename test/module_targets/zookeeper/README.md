# Native ZooKeeper information targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb zookeeper
```

The bounded family runs official digest-pinned ZooKeeper 3.4.14 and 3.9.3 images.
The legacy image is Linux amd64. Profiles permit both `envi` and `stat`, permit
each separately, or retain the modern image's restricted `srvr` policy. These
are genuine vendor command permissions, with no replacement protocol handler.
Server heap settings keep these single-node information fixtures small.

Independent vendor CLI, generated configuration and complete native four-letter
TCP reads prove each policy, actual server version and environment/statistics
before Framework runs. Collected environment loot must retain native identity
fields; statistics must retain the native version, mode and node count. Live
memory/counter values are structurally checked rather than assumed constant.
Every permission profile repeats, with no unexpected loot on denied paths.
Zero/default and one-second probe timeout settings are exercised on healthy
targets. Unrelated actual Apache must not yield ZooKeeper loot.

See the official [command documentation](https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_zkCommands)
and [image configuration](https://hub.docker.com/_/zookeeper). The legacy
entrypoint does not support the newer whitelist environment variable; both
versions use its actual supported `ZOO_CFG_EXTRA` configuration instead. The
restricted modern profile uses the image's documented `srvr` setting.

Only random loopback client ports are published. Other releases/architectures,
TLS/SASL client operations, ensembles/quorum changes and administration through
the HTTP command server remain outside this profile. Registration alone is not
a passing result. The [shared guide](../README.md) explains exact source/count
and owned teardown gates. Existing human Scenarios are not fabricated.
