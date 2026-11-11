# Fixed Ray log API comparison

Run this profile serially with the affected [log enumeration owner](../ray_logs_enum/README.md):

```sh
DOCKER_CONTEXT=default BUILDX_BUILDER=default nice -n 10 bundle exec ruby tools/dev/run_guarded_module_target_tests.rb ray_logs_enum ray_logs_fixed
```

The pinned official 2.57.0 image uses the same normal full dashboard and resource
limits: three containers, at most 5,952 MiB and 2.1 CPUs, including Framework.
The [upstream fix](https://github.com/ray-project/ray/pull/64701) validates glob
paths in the genuine log agent. Before/after controls verify installed sources,
an actual task, ordinary SDK log listing/retrieval and direct HTTP traversal
denials. Existing outside fixtures remain present throughout the owner tests.

Seven functional examples cover repeated Safe checks, automatic refusal, forced
traversal/absolute-path denials, exact ordinary-log loot and invalid
node/unrelated-service negatives. A configured profile alone is not passing
evidence. This single-node comparison does not qualify other releases or nodes.

The installed wheel reports commit `4464bbb6e21bce4893ed3396b2e33996188d511d`;
the 2.57.0 tag is `878455a3d8f5bcea569d8c40a39b7b5681a55125`.
All eleven selected installed source files must match the pinned manifest.
Both revisions were independently fetched for comparison. This keeps package
identity distinct from a version string or tag assertion.
