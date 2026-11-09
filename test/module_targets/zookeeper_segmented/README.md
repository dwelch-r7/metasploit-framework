# ZooKeeper through a sliced native TCP stream

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb zookeeper_segmented
```

The profile reuses the genuine pinned 3.9.3 server and the
[shared Toxiproxy component](../tcp_proxy/README.md). Its downstream slicer uses
a configured average size of 640 bytes and a 150-millisecond delay. Actual chunk
sizes are retained; Toxiproxy can balance pieces below that configured average.
Native EOF reads verify complete
environment/statistics replies and the actual applied configuration, with no
substituted service bytes. Dynamic memory and statistics values are compared
by their actual schema/identity rather than assuming separate reads are equal.

The single case repeats module collection and requires complete loot through
the altered stream, using the module's own five-second TIMEOUT option. The
normal [version/permission profile](../zookeeper/README.md) retains its shorter
probe settings. Registration alone is not a qualification result. Raw source,
native wire chunks and teardown evidence must establish the outcome.
