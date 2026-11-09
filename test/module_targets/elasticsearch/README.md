# Elasticsearch enumeration qualification

Run from the repository root and inspect the retained assertions, input hashes
and owned cleanup before claiming qualification:

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb elasticsearch
```

The vendor's digest-pinned Elasticsearch 7.9.1 image supplies two genuine
single-node clusters: security disabled and native Basic authentication enabled.
Each has a 256-MiB Java heap, no published transport port, and a random loopback
HTTP port. Memory-mapped stores are disabled, so no host sysctl change is needed.
No external cluster, host data directory, socket or additional capability is used.

See the [versioned Docker guide](https://www.elastic.co/guide/en/elasticsearch/reference/7.9/docker.html)
and [memory-mapping setting](https://www.elastic.co/guide/en/elasticsearch/reference/7.9/index-modules-store.html).
The secured fixture uses public account `elastic` / `module-target-password`.
Native REST requests seed seven small records and an empty index, verify exact
stored bytes, authentication and permissions, and retain actual cluster/node/
index/user responses before Framework execution. A genuine Apache service is
the unrelated HTTP control. All seeded state belongs to the disposable lab.

Functional qualification must assert actual metadata and parsed CSV loot,
bounded row selection, empty-data behavior, authentication/permission negatives
and unrelated-service refusal. A completing console command alone is not proof.
The fixture uses flat, consistent source fields. Other versions, multi-node
clusters, TLS, heterogeneous/nested source schemas, source-disabled indices,
legacy vulnerable scripting and database persistence remain unqualified.
