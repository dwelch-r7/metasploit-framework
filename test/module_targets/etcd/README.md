# Native etcd version and v2 key targets

```sh
bundle exec ruby tools/dev/run_module_target_tests.rb etcd
```

The bounded family uses official digest-pinned etcd 3.4.35 and 3.5.18 images.
The older image is Linux amd64; the newer index is multiarchitecture, but only
the actually recorded test platform is qualified. Profiles explicitly enable
the legacy v2 API, retain its disabled setting, enable actual v2 authentication,
or leave the key store empty. A real Apache reverse proxy supplies a base path;
ordinary Apache JSON/HTML is the unrelated-service control.

Independent native preflight checks server/CLI versions and health, writes and
recursively reads nested keys including Unicode/newlines, verifies exact values
and the empty store, and exercises real accepted/denied authentication. It also
proves the disabled v2 endpoint returns 404 while the actual v3 API works.
Module discovery must match the genuine version, collection must produce valid
JSON loot identical to the native recursive document, and repeated collection
must preserve the key tree. Denied, unsupported and unrelated targets must not
produce key loot or runtime exceptions. An unrelated JSON version resource must
not be reported as etcd. Registration alone does not qualify these assertions.
Directory-child arrays are ordered by their native keys for comparison because
ordinary recursive reads return them in varying order; every field, index and
value remains part of the exact comparison.

The etcd v2 API and its authentication are distinct from v3. These modules
implement v2 collection; this profile does not claim v3 key enumeration, TLS,
client certificates, multi-member failure handling or later releases. See the
official [container guide](https://etcd.io/docs/v3.5/op-guide/container/),
[v2 authentication API](https://etcd.io/docs/v2.3/auth_api/) and
[v3.5 configuration](https://etcd.io/docs/v3.5/op-guide/configuration/).

Only random loopback ports are exposed; all target state belongs to a fresh
Compose project. The [shared guide](../README.md) explains retained native
responses, source hashes, exact counts and teardown. Existing human module
Scenarios are not replaced or fabricated.
